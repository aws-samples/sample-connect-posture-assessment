"""
Contact-flow security checks (Phase 2 / Task 5).

These checks parse contact flow JSON content (via the parser package) and
detect security vulnerabilities in the flow logic:

- sec-prompt-inject-001       : Dynamic prompt injection risk
- sec-lambda-validation-001   : Lambda response used for branching without validation
- sec-toll-fraud-001          : External transfer to dynamic phone number (toll fraud)
- sec-sensitive-data-001      : Sensitive data stored in contact attributes
- sec-pii-prompts-001         : PII read back in voice prompts without masking
- sec-output-handling-001     : External output piped to actions without sanitization

Each check operates on a parsed ContactFlowGraph derived from the flow content.
"""

import re
from typing import Dict, List, Optional

from ..models import (
    CheckStatus,
    ContactFlow,
    ContactFlowGraph,
    FlowAction,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from ..parsers import ContactFlowParser
from .base import BaseCheck, CheckContext

_PARSER = ContactFlowParser()

# Patterns indicating sensitive data in attribute names (case-insensitive).
# These are DETECTION substrings for flagging PII/PCI/PHI stored in contact
# attributes — not recommended attribute names for customer use. A match should
# trigger a compliance review (HIPAA, PCI-DSS, or GDPR as applicable).
_SENSITIVE_ATTR_PATTERNS = (
    "ssn",
    "social",
    "creditcard",
    "cardnumber",
    "cvv",
    "pin",
    "password",
    "passcode",
    "dob",
    "dateofbirth",
    "accountnumber",
    "routingnumber",
    "bankaccount",
    "taxid",
    "passportnumber",
)

# Action types that collect external/untrusted data.
_EXTERNAL_DATA_ACTIONS = {
    "InvokeLambdaFunction",
    "ConnectToLexBot",
    "ConnectParticipantWithLexBot",
    "GetParticipantInput",
    "GetUserInput",
    "StoreUserInput",
}

# Transfer-to-phone-number action type variants.
_PHONE_TRANSFER_TYPES = {
    "TransferContactToPhoneNumber",
    "TransferToPhoneNumber",
}


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    """Parse a ContactFlow's content into a graph; return None on failure."""
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return _PARSER.parse(flow.content)
    except Exception:
        return None


def _is_dynamic_reference(value) -> bool:
    """True if the value references a contact attribute or external source."""
    if not isinstance(value, str):
        return False
    return value.startswith("$.") or value.startswith("$[")


# Matches a JSONPath-style contact attribute reference embedded anywhere in
# free text, e.g. the "$.Attributes.Name" in "Hello, $.Attributes.Name.".
# Captures $.<segment>(.<segment>|[...])* — stops at whitespace or a
# JSONPath-illegal character so trailing punctuation in prose ("...Name.")
# isn't swallowed into the reference.
_DYNAMIC_REF_PATTERN = re.compile(r"\$(?:\.[A-Za-z0-9_]+|\[[^\]]*\])+")


# JSONPath root segments for Amazon Connect's *system* attributes — see
# https://docs.aws.amazon.com/connect/latest/adminguide/connect-attrib-list.html.
# These are predefined, Connect-populated values that a flow author cannot
# redefine and a caller cannot set to arbitrary text (queue/agent names
# configured by the admin, region/channel/contact-id metadata, telephony
# SIP headers from the carrier). They are excluded from
# DynamicPromptInjectionCheck's flags: a $.Queue.Name reference in a
# prompt is not an injection vector the way a value sourced from caller
# DTMF input, a Lex slot, or a Lambda/CRM lookup is, because nothing the
# caller says or does changes what these resolve to. Listed by root
# segment so nested paths (e.g. $.Queue.OutboundCallerId.Address) match
# too.
_SYSTEM_ATTRIBUTE_ROOTS = (
    "$.awsregion",
    "$.systemendpoint",
    "$.queue",
    "$.agent",
    "$.contactid",
    "$.initialcontactid",
    "$.taskcontactid",
    "$.previouscontactid",
    "$.channel",
    "$.instancearn",
    "$.initiationmethod",
    "$.languagecode",
    "$.tags",
    "$.media.sip",
)


def _is_system_attribute_reference(value: str) -> bool:
    """
    True if ``value`` is a Connect *system* attribute reference (queue
    name, agent name, region, channel, contact ID, carrier SIP metadata,
    etc) rather than a value that originated from the caller, a bot slot,
    or a Lambda/external lookup.

    Used to keep DynamicPromptInjectionCheck focused on genuine injection
    risk: system attributes are admin-configured or Connect-populated and
    a caller cannot influence what they resolve to, so speaking one in a
    prompt carries none of the SSML-injection risk this check exists to
    catch.
    """
    lowered = value.lower()
    return any(lowered.startswith(root) for root in _SYSTEM_ATTRIBUTE_ROOTS)


def _get_phone_destination(action: FlowAction) -> Optional[str]:
    """Extract the phone number destination from a transfer action."""
    params = action.parameters or {}
    return (
        params.get("PhoneNumber")
        or params.get("ContactFlowId")  # some older formats
        or params.get("Endpoint", {}).get("Address")
        if isinstance(params.get("Endpoint"), dict)
        else params.get("PhoneNumber")
    )


class DynamicPromptInjectionCheck(BaseCheck):
    """Detect dynamic content in voice prompts without validation (Req 20)."""

    def __init__(self):
        super().__init__(
            check_id="sec-prompt-inject-001",
            name="Dynamic Prompt Injection Risk",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Detects contact flows that insert unsanitized dynamic content "
                "(attributes, Lambda returns) into voice prompts or SSML."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []
        system_attr_refs_seen = 0

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type not in (
                    "MessageParticipant",
                    "PlayPrompt",
                    "PlayAudio",
                ):
                    continue
                text = str(action.parameters.get("Text", ""))
                dynamic_refs = _DYNAMIC_REF_PATTERN.findall(text)
                if not dynamic_refs:
                    continue
                # $.Queue.Name, $.Agent.*, and the other system attributes
                # in _SYSTEM_ATTRIBUTE_ROOTS are Connect-populated and
                # admin-configured — a caller cannot set what they resolve
                # to, so speaking one carries none of the SSML-injection
                # risk this check exists to catch. Skip a prompt whose
                # *only* dynamic references are system attributes; a
                # prompt mixing a system attribute with a caller-sourced
                # one is still flagged, since the caller-sourced part is
                # the actual risk.
                if all(_is_system_attribute_reference(ref) for ref in dynamic_refs):
                    system_attr_refs_seen += 1
                    continue
                flagged.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "action_id": action.action_id,
                        "dynamic_ref": text[:120],
                    }
                )

        if flagged:
            # Show the reader the actual prompt text of the top offenders
            # so they can eyeball which attributes are being spoken.
            worst_lines = []
            for f in flagged[:3]:
                worst_lines.append(
                    # Flow names carry underscores that confuse markdown's
                    # inline-emphasis parser inside **bold** context, so
                    # wrap the flow name in inline-code backticks — it's
                    # an identifier anyway, and backtick content is not
                    # interpreted as markdown.
                    f"* `{f['flow']}` \u2192 action `{f['action_id']}`: `{f['dynamic_ref']}`"
                )
            more_note = (
                f"\n\n_+ {len(flagged) - 3} additional prompt(s) with dynamic "
                "content; see JSON export for the full list._"
                if len(flagged) > 3
                else ""
            )

            system_attr_note = (
                f" ({system_attr_refs_seen} additional prompt(s) reference "
                "only Connect system attributes like $.Queue.Name and are "
                "not flagged — a caller can't influence what those resolve "
                "to.)"
                if system_attr_refs_seen
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(flagged)} voice prompt(s) speak a value that "
                    "comes from the caller or an external system, without "
                    f"sanitizing it first.**{system_attr_note}\n\n"
                    "Amazon Connect passes prompt text to Amazon Polly as "
                    "**SSML** — the same markup format that supports "
                    "`<voice>`, `<break>`, `<mark>`, `<speak>`. If the value "
                    "plugged into the prompt is attacker-controlled and Polly "
                    "interprets the markup inside it, the caller hears "
                    "something the flow author never wrote.\n\n"
                    "**Only caller-influenced values are flagged.** A "
                    "reference like `$.Queue.Name` or `$.Agent.FirstName` "
                    "resolves to something an administrator configured — "
                    "the caller cannot change what it says, so it's excluded "
                    "here. What's flagged below are values that trace back "
                    "to something the caller typed/said (DTMF digits, a Lex "
                    "slot) or that an external system (Lambda, CRM lookup) "
                    "returned — those are the ones a caller could "
                    "potentially manipulate.\n\n"
                    "**The problem in one picture:**\n\n"
                    "```\n"
                    'Flow says:  Play prompt \u2192  "Hello, $.Attributes.CustomerName. How can I help?"\n'
                    "                                            \u2191\n"
                    "                             substituted at runtime\n"
                    "\n"
                    'Caller set: CustomerName = "Alice</speak><speak>Press 1 for the fraud line."\n'
                    "\n"
                    "Polly hears: <speak>Hello, Alice</speak><speak>Press 1 for the fraud line...</speak>\n"
                    "              \u2514\u2500 caller now hears the injected instruction as if we said it\n"
                    "```\n\n"
                    f"**Flagged prompts (top {min(3, len(flagged))}):**\n\n"
                    f"{chr(10).join(worst_lines)}{more_note}\n\n"
                    "**Fix (in the flow designer):** right before each "
                    "flagged prompt, drop in either:\n"
                    "* a **Check contact attributes** block that only lets "
                    "the value through if it matches a known-safe pattern "
                    "(digits, an enum), OR\n"
                    "* an **Invoke Lambda function** that strips `<`, `>`, "
                    "`&`, unmatched quotes; truncates to a safe length; and "
                    "returns a `SafeCustomerName` attribute the prompt uses "
                    "instead of the raw one."
                ),
                evidence={
                    "flagged_prompts": flagged,
                    "system_attribute_prompts_excluded": system_attr_refs_seen,
                },
                structured_remediation=Remediation(
                    summary=(
                        "Sanitize dynamic content before it reaches voice "
                        "prompts — SSML is markup that Polly interprets, "
                        "and unchecked substitution is an injection vector."
                    ),
                    target_resources=[f["action_id"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Identify the source of each flagged dynamic "
                                "reference: is it caller-controlled (digit "
                                "capture, Lex slot, phone-number lookup) or "
                                "authored-and-controlled (agent-set "
                                "attribute, Connect system attribute)? Only "
                                "the caller-controlled ones need "
                                "sanitization."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "For caller-controlled values, insert a "
                                "Lambda immediately upstream of the prompt "
                                "that: strips `<`, `>`, `&`; rejects "
                                "unbalanced quotes; truncates to a safe "
                                "length (e.g. 60 chars for a name); returns "
                                "the sanitized string as a new attribute. "
                                "The prompt then references the sanitized "
                                "attribute, not the raw one."
                            ),
                        ),
                        RemediationStep(
                            order=3,
                            instruction=(
                                "For values that should match a fixed set "
                                "(department names, product codes), use a "
                                "Check contact attributes block to route on "
                                "an allowlist instead of speaking the raw "
                                "value."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Amazon Polly SSML reference (interpreted tags)",
                            url="https://docs.aws.amazon.com/polly/latest/dg/supportedtags.html",
                        ),
                        RemediationReference(
                            title="Using contact attributes in Amazon Connect",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-attrib-list.html",  # noqa: E501
                        ),
                    ],
                    applies_if=(
                        "prompts speak values that originated from callers or "
                        "external systems (as opposed to hard-coded strings)."
                    ),
                ),
            )

        system_attr_note = (
            f" ({system_attr_refs_seen} prompt(s) reference only Connect "
            "system attributes like $.Queue.Name, which are excluded since "
            "a caller can't influence them.)"
            if system_attr_refs_seen
            else ""
        )
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"None of the {len(instance.contact_flows)} contact flow(s) "
                "analyzed have a voice prompt that speaks a caller- or "
                f"external-system-sourced value.{system_attr_note} Every "
                "prompt either uses a hard-coded string, or its only "
                "dynamic reference is a Connect system attribute the caller "
                "cannot influence — neither is a vector for the SSML "
                "injection this check looks for (malicious `</speak><speak>` "
                "markup or attacker-authored text smuggled through a value "
                "the caller controls)."
            ),
            evidence={
                "flows_analyzed": len(instance.contact_flows),
                "system_attribute_prompts_excluded": system_attr_refs_seen,
            },
        )


class LambdaResponseValidationCheck(BaseCheck):
    """Detect Lambda returns used for branching without validation (Req 21)."""

    def __init__(self):
        super().__init__(
            check_id="sec-lambda-validation-001",
            name="Lambda Response Validation",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description=(
                "Detects contact flows that branch on Lambda return values "
                "without validating the response shape or providing a default."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type != "InvokeLambdaFunction":
                    continue
                # Check if action's transitions include conditions (branching
                # on the return). If conditions exist but no default/error path,
                # it's unvalidated branching.
                cond_targets = [t for t in action.transitions if t.transition_type == "condition"]
                has_default = any(t.transition_type == "default" for t in action.transitions)
                if cond_targets and not has_default:
                    flagged.append(
                        {
                            "flow": flow.name,
                            "flow_id": flow.id,
                            "action_id": action.action_id,
                            "lambda_arn": action.parameters.get("FunctionArn", "unknown"),
                        }
                    )

        if flagged:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(flagged)} Lambda invocation(s) branch on return "
                    "values without a default fallback path."
                ),
                evidence={"flagged_lambdas": flagged},
                structured_remediation=Remediation(
                    summary="Add default/fallback branches after Lambda invocations.",
                    target_resources=[f["action_id"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each flagged Lambda action, add a 'Default' "
                                "transition that handles unexpected return values "
                                "safely (e.g., route to an error prompt or retry)."
                            ),
                        ),
                    ],
                    applies_if="Lambda functions may return unexpected data.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description="Lambda branching includes default paths.",
            evidence={"flows_analyzed": len(instance.contact_flows)},
        )


class ExternalTransferTollFraudCheck(BaseCheck):
    """Detect dynamic phone-number transfers (toll fraud risk, Req 22)."""

    def __init__(self):
        super().__init__(
            check_id="sec-toll-fraud-001",
            name="External Transfer Toll Fraud Risk",
            pillar=Pillar.SECURITY,
            severity=Severity.CRITICAL,
            description=(
                "Detects contact flows that transfer calls to dynamically "
                "determined phone numbers without a validation step, "
                "exposing the instance to toll fraud."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []
        static_count = 0

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type not in _PHONE_TRANSFER_TYPES:
                    continue
                dest = _get_phone_destination(action)
                if dest and _is_dynamic_reference(dest):
                    flagged.append(
                        {
                            "flow": flow.name,
                            "flow_id": flow.id,
                            "action_id": action.action_id,
                            "dynamic_source": dest,
                        }
                    )
                else:
                    static_count += 1

        if flagged:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(flagged)} external transfer(s) use a dynamic phone "
                    "number without validation — toll fraud risk."
                ),
                evidence={
                    "dynamic_transfers": flagged,
                    "static_transfers": static_count,
                },
                structured_remediation=Remediation(
                    summary="Constrain dynamic transfer destinations to an allowlist.",
                    target_resources=[f["action_id"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Add a Check Attribute or Lambda validation "
                                "action before the transfer that confirms the "
                                "destination number is on a pre-approved list."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Alternatively, replace the dynamic reference "
                                "with a static, hardcoded number for each "
                                "known destination."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Transfer contacts to a phone number",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/transfer-to-phone-number.html",  # noqa: E501
                        )
                    ],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(f"All {static_count} external transfer(s) use static phone numbers."),
            evidence={"static_transfers": static_count},
        )


class SensitiveDataInAttributesCheck(BaseCheck):
    """Detect sensitive data stored in contact attributes (Req 23)."""

    def __init__(self):
        super().__init__(
            check_id="sec-sensitive-data-001",
            name="Sensitive Data in Contact Attributes",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Detects contact flows that store potentially sensitive data "
                "(PII, credentials) in contact attributes, which are visible "
                "in CTRs, logs, and reporting."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type not in (
                    "UpdateContactAttributes",
                    "SetContactAttributes",
                ):
                    continue
                attrs = action.parameters.get("Attributes", {})
                if isinstance(attrs, dict):
                    for key in attrs:
                        if any(p in key.lower() for p in _SENSITIVE_ATTR_PATTERNS):
                            flagged.append(
                                {
                                    "flow": flow.name,
                                    "flow_id": flow.id,
                                    "action_id": action.action_id,
                                    "attribute_name": key,
                                }
                            )

        if flagged:
            # Group flagged items by flow so the reader can jump to each
            # flow once rather than scanning a de-duplicated action list.
            by_flow: Dict[str, List[Dict[str, str]]] = {}
            for f in flagged:
                by_flow.setdefault(f["flow"], []).append(f)

            flow_lines = []
            for flow_name, entries in list(by_flow.items())[:5]:
                attr_names = ", ".join(sorted({f"`{e['attribute_name']}`" for e in entries}))
                flow_lines.append(f"* `{flow_name}` — sets: {attr_names}")
            more_note = (
                f"\n\n_+ {len(by_flow) - 5} more flow(s) with flagged attributes; see JSON export._"
                if len(by_flow) > 5
                else ""
            )

            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(flagged)} `Set contact attributes` action(s) in "
                    f"{len(by_flow)} flow(s) store data under names that "
                    "look like PII or credentials.**\n\n"
                    "The attribute name is the giveaway — this check "
                    "watches for keys like `ssn`, `dob`, `creditcard`, "
                    "`cvv`, `pin`, `password`, `accountnumber`, "
                    "`bankaccount`, `taxid`, `passportnumber` (full list in "
                    "the source). If a Connect flow writes those names into "
                    "contact attributes, the values end up in three places "
                    "you probably don't want them:\n\n"
                    "1. **Contact Trace Records (CTRs)** — attributes are "
                    "part of the CTR JSON exported to your Kinesis or S3 "
                    "stream after every contact. Anyone with read on that "
                    "bucket sees the raw value.\n"
                    "2. **Agent workspace** — supervisors and agents with "
                    "'View contact record' permission can see attributes "
                    "on a completed contact.\n"
                    "3. **Flow logs / CloudWatch** — if flow logging is "
                    "enabled, every attribute change writes a log line "
                    "containing the value.\n\n"
                    "**What the check flagged:**\n\n"
                    f"{chr(10).join(flow_lines)}{more_note}\n\n"
                    "**Fix (per attribute):** keep the *reference*, drop "
                    "the *value*. In the flow, replace:\n\n"
                    "```\n"
                    "Set contact attribute:  ssn        = <raw 9-digit value>\n"
                    "```\n\n"
                    "with:\n\n"
                    "```\n"
                    "Set contact attribute:  ssn_last4  = <last 4 digits only>       # safe to voice/log\n"
                    "Set contact attribute:  customer_token = <Lambda-returned UUID>  # opaque handle\n"
                    "```\n\n"
                    "Store the full value in Amazon Connect Customer "
                    "Profiles (encrypted at rest, access-scoped) and "
                    "resolve it via Lambda only when a specific step needs "
                    "the full number. The attribute in the flow then "
                    "carries only the token — logs and CTRs stay clean."
                ),
                evidence={"flagged_attributes": flagged},
                structured_remediation=Remediation(
                    summary=(
                        "Replace raw-PII contact attributes with tokenized "
                        "references; resolve the full value via Lambda "
                        "only when a step needs it."
                    ),
                    target_resources=[f["action_id"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each flagged attribute, decide the "
                                "smallest form the flow actually needs: "
                                "last-4 digits for confirmation prompts, "
                                "an opaque token for downstream Lambdas, "
                                "or nothing at all if the value was "
                                "written but never read."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Move the full value into Amazon Connect "
                                "Customer Profiles (or your own encrypted "
                                "store) keyed by a UUID. Update the flow "
                                "to store only the UUID as a contact "
                                "attribute; write a small Lambda that "
                                "returns the full value on demand for the "
                                "one or two blocks that need it."
                            ),
                            console_path=("Connect console -> Customer Profiles"),
                        ),
                        RemediationStep(
                            order=3,
                            instruction=(
                                "If you can't avoid attributes at all, at "
                                "least enable Contact Lens sensitive-data "
                                "redaction so the values are scrubbed "
                                "before CTRs and recordings are exported."
                            ),
                            console_path=("Connect console -> Analytics -> Contact Lens settings"),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Customer Profiles for Amazon Connect",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/customer-profiles.html",  # noqa: E501
                        ),
                        RemediationReference(
                            title="Contact Lens sensitive data redaction",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/sensitive-data-redaction.html",  # noqa: E501
                        ),
                    ],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"None of the {len(instance.contact_flows)} flow(s) "
                "analyzed store data under attribute names that look like "
                "PII or credentials (ssn, dob, creditcard, cvv, pin, "
                "accountnumber, etc.). If PII passes through a flow at "
                "all, this pattern keeps it out of CTRs and flow logs — "
                "which is where accidental exposure usually happens."
            ),
            evidence={"flows_analyzed": len(instance.contact_flows)},
        )


class PIIInPromptsCheck(BaseCheck):
    """Detect PII read back in voice prompts without masking (Req 39)."""

    def __init__(self):
        super().__init__(
            check_id="sec-pii-prompts-001",
            name="PII Exposure in Voice Prompts",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Detects contact flows that read back sensitive customer data "
                "(account numbers, SSN, etc.) in voice prompts without masking."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type not in ("MessageParticipant", "PlayPrompt"):
                    continue
                raw_text = str(action.parameters.get("Text", ""))
                text = raw_text.lower()
                for pattern in _SENSITIVE_ATTR_PATTERNS:
                    if pattern in text:
                        # Check if masking is applied (heuristic: "last4",
                        # "ending in", "substring" in same text).
                        has_mask = any(
                            m in text
                            for m in (
                                "last4",
                                "lastfour",
                                "ending in",
                                "substring",
                                "mask",
                                "redact",
                            )
                        )
                        if not has_mask:
                            # Preserve a truncated copy of the raw prompt
                            # text so the finding can show the reader
                            # what actually got flagged.
                            excerpt = raw_text.replace("\n", " ").strip()
                            if len(excerpt) > 140:
                                excerpt = excerpt[:137] + "\u2026"
                            flagged.append(
                                {
                                    "flow": flow.name,
                                    "flow_id": flow.id,
                                    "action_id": action.action_id,
                                    "attribute_pattern": pattern,
                                    "prompt_text": excerpt,
                                }
                            )
                        break  # one flag per action is enough

        if flagged:
            worst_lines = []
            for f in flagged[:3]:
                worst_lines.append(
                    f"* `{f['flow']}` \u2192 matches `{f['attribute_pattern']}` "
                    f"in prompt: \u201c{f['prompt_text']}\u201d"
                )
            more_note = (
                f"\n\n_+ {len(flagged) - 3} more prompt(s); see JSON export._"
                if len(flagged) > 3
                else ""
            )

            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(flagged)} voice prompt(s) speak a piece of "
                    "sensitive data back to the caller without masking "
                    "it.**\n\n"
                    "The check reads the `Text` parameter of every "
                    "`Play prompt` / `Message participant` action, looks "
                    "for references to values that sound like PII "
                    "(`ssn`, `dob`, `creditcard`, `accountnumber`, "
                    "`taxid`, `passportnumber`, and similar), and checks "
                    "whether the prompt also contains a masking hint "
                    "nearby (`last4`, `ending in`, `substring`, `mask`, "
                    "`redact`). If the sensitive reference is present but "
                    "no masking hint is, the prompt gets flagged.\n\n"
                    "**Unmasked vs masked, side by side:**\n\n"
                    "```\n"
                    '\u274c  Play prompt: "Your account number is $.Attributes.AccountNumber."\n'
                    "         \u2514\u2500 caller hears all 12 digits, anyone nearby hears them too.\n"
                    "\n"
                    '\u2705  Play prompt: "Your account ending in $.Attributes.AccountNumberLast4."\n'
                    "         \u2514\u2500 last 4 digits only, enough for the caller to recognize.\n"
                    "```\n\n"
                    "**Why this matters.** Callers phone from open "
                    "offices, cars, and public spaces. Whatever the "
                    "prompt says gets heard by anyone in earshot AND is "
                    "captured verbatim in the call recording. Recordings "
                    "sit in S3 for weeks or years. If a support team, "
                    "auditor, or breached recording bucket touches the "
                    "recordings later, the PII is right there in the "
                    "audio.\n\n"
                    "**What the check flagged:**\n\n"
                    f"{chr(10).join(worst_lines)}{more_note}\n\n"
                    "**Fix (per prompt):** replace the full attribute "
                    "reference with a `*Last4` variant, or a "
                    "confirmation pattern that doesn't voice the value "
                    "at all (\u201cThe account ending in 4 3 2 1, is that "
                    "correct?\u201d). Compute the last-4 attribute with a "
                    "small `Set contact attributes` block upstream of "
                    "the prompt. Additionally, turn on **Contact Lens "
                    "sensitive-data redaction** so if a caller says the "
                    "full number back, it's redacted from the recording "
                    "and transcript."
                ),
                evidence={"flagged_prompts": flagged},
                structured_remediation=Remediation(
                    summary=(
                        "Voice only the last 4 digits (or a tokenized "
                        "reference) instead of the full value, and turn "
                        "on Contact Lens redaction as a safety net."
                    ),
                    target_resources=[f["action_id"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each flagged prompt, compute a "
                                "last-4 attribute upstream (Set contact "
                                "attributes \u2192 "
                                "`AccountNumberLast4 = $.Attributes.AccountNumber` "
                                "with a substring transform), then edit "
                                "the prompt to reference the last-4 "
                                "attribute instead of the full one."
                            ),
                            console_path="Connect console -> Routing -> Flows",
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Enable Contact Lens sensitive-data "
                                "redaction on the instance. This scrubs "
                                "numeric PII patterns (account numbers, "
                                "SSNs, credit cards) from call "
                                "recordings and transcripts before they "
                                "land in S3."
                            ),
                            console_path=("Connect console -> Analytics -> Contact Lens settings"),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Contact Lens sensitive data redaction",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/sensitive-data-redaction.html",  # noqa: E501
                        )
                    ],
                    applies_if=("prompts include values that identify or authenticate a customer."),
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"None of the {len(instance.contact_flows)} flow(s) "
                "analyzed voice sensitive attributes (ssn, dob, "
                "creditcard, accountnumber, etc.) to callers without a "
                "masking hint nearby (`last4`, `ending in`, `substring`, "
                "`mask`, `redact`). This is the pattern that keeps PII "
                "out of call recordings and stops passers-by in the "
                "caller's environment from overhearing account numbers."
            ),
            evidence={"flows_analyzed": len(instance.contact_flows)},
        )


class OutputHandlingInjectionCheck(BaseCheck):
    """Detect external output piped to actions without sanitization (Req 26)."""

    def __init__(self):
        super().__init__(
            check_id="sec-output-handling-001",
            name="Contact Flow Output Handling / Injection Prevention",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Detects data-flow paths where external outputs (Lambda, Lex) "
                "reach downstream actions (prompts, transfers, subsequent "
                "invocations) without intermediate validation."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue

            # Walk each external-data action and check what follows it.
            for action in graph.actions.values():
                if action.action_type not in _EXTERNAL_DATA_ACTIONS:
                    continue
                # Look at immediate successors for high-risk consumers.
                for t in action.transitions:
                    succ = graph.actions.get(t.target_action_id)
                    if not succ:
                        continue
                    # Prompt right after external data = injection path.
                    if succ.action_type in ("MessageParticipant", "PlayPrompt"):
                        text = str(succ.parameters.get("Text", ""))
                        if "$." in text:
                            flagged.append(
                                {
                                    "flow": flow.name,
                                    "flow_id": flow.id,
                                    "source_action": action.action_id,
                                    "consumer_action": succ.action_id,
                                    "path": "external -> prompt (no validation)",
                                }
                            )
                    # Transfer after external data = routing manipulation.
                    if succ.action_type in _PHONE_TRANSFER_TYPES:
                        dest = _get_phone_destination(succ)
                        if dest and _is_dynamic_reference(dest):
                            flagged.append(
                                {
                                    "flow": flow.name,
                                    "flow_id": flow.id,
                                    "source_action": action.action_id,
                                    "consumer_action": succ.action_id,
                                    "path": "external -> transfer (no validation)",
                                }
                            )

        if flagged:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(flagged)} output-handling injection path(s) detected "
                    "where external data flows to prompts or transfers without "
                    "intermediate validation."
                ),
                evidence={"injection_paths": flagged},
                structured_remediation=Remediation(
                    summary=(
                        "Insert validation between external data sources and "
                        "downstream consumers (prompts, transfers)."
                    ),
                    target_resources=[f["source_action"] for f in flagged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Add a Check Attribute or Lambda sanitization "
                                "step between the external data source and the "
                                "consuming action. Validate that the value "
                                "matches expected format/allowlist."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="OWASP LLM05: Improper Output Handling",
                            url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",  # noqa: E501
                        )
                    ],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description="No unvalidated external-output injection paths detected.",
            evidence={"flows_analyzed": len(instance.contact_flows)},
        )


def register_contact_flow_security_checks(registry) -> None:
    """Register all contact-flow security checks."""
    registry.register_check(DynamicPromptInjectionCheck())
    registry.register_check(LambdaResponseValidationCheck())
    registry.register_check(ExternalTransferTollFraudCheck())
    registry.register_check(SensitiveDataInAttributesCheck())
    registry.register_check(PIIInPromptsCheck())
    registry.register_check(OutputHandlingInjectionCheck())
