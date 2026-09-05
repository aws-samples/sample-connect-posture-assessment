"""
Contact Flow Analyzer for Amazon Connect Assessment Tool.

This module provides functionality to analyze Amazon Connect contact flows,
extracting configuration details, flow logic, and integration points.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from ..models import ConnectInstance, ContactFlow
from .base import BaseAnalyzer


class ContactFlowAnalyzer(BaseAnalyzer):
    """
    Analyzer for Amazon Connect contact flows.

    Analyzes contact flow configurations including flow logic, error handling,
    integration points, and security settings within Connect instances.
    """

    def __init__(self, aws_client_factory, config: Dict[str, Any] = None):
        """
        Initialize the Contact Flow Analyzer.

        Args:
            aws_client_factory: AWSClientFactory instance for AWS service clients
            config: Optional configuration dictionary for analyzer behavior
        """
        super().__init__(aws_client_factory, config)
        self.logger = logging.getLogger("analyzer.ContactFlowAnalyzer")

    def analyze(self, instance: ConnectInstance) -> ConnectInstance:
        """
        Analyze contact flows for a Connect instance.

        Args:
            instance: ConnectInstance object to populate with contact flow data

        Returns:
            ConnectInstance: Updated instance with contact flow analysis data
        """
        try:
            self.logger.debug(f"Analyzing contact flows for instance {instance.instance_id}")

            contact_flows = self._discover_contact_flows(instance.instance_id)
            instance.contact_flows = contact_flows

            self.logger.info(
                f"Analyzed {len(contact_flows)} contact flows for instance {instance.instance_id}"
            )
            return instance

        except Exception as e:
            self.logger.error(
                f"Failed to analyze contact flows for instance {instance.instance_id}: {str(e)}"
            )
            raise

    def _discover_contact_flows(self, instance_id: str) -> List[ContactFlow]:
        """
        Discover and analyze all contact flows in a Connect instance.

        Args:
            instance_id: The Connect instance ID

        Returns:
            List[ContactFlow]: List of analyzed contact flows
        """
        contact_flows = []

        try:
            # List all contact flows
            for page in self.paginate_api_resilient(
                self.connect_client,
                "list_contact_flows",
                "connect",
                InstanceId=instance_id,
            ):
                contact_flow_summaries = page.get("ContactFlowSummaryList", [])

                for flow_summary in contact_flow_summaries:
                    try:
                        contact_flow = self._analyze_contact_flow(instance_id, flow_summary)
                        contact_flows.append(contact_flow)
                        self.logger.debug(
                            f"Analyzed contact flow: {contact_flow.name} ({contact_flow.type})"
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Failed to analyze contact flow {flow_summary.get('Id', 'unknown')}: {str(e)}"
                        )
                        if not self.is_resource_not_found(e):
                            raise

            return contact_flows

        except Exception as e:
            self.logger.error(f"Failed to discover contact flows: {str(e)}")
            raise

    def _analyze_contact_flow(self, instance_id: str, flow_summary: Dict[str, Any]) -> ContactFlow:
        """
        Analyze a single contact flow and extract detailed configuration.

        Args:
            instance_id: The Connect instance ID
            flow_summary: Contact flow summary from list_contact_flows API

        Returns:
            ContactFlow: Analyzed contact flow object
        """
        flow_id = flow_summary["Id"]
        flow_arn = flow_summary["Arn"]
        flow_name = flow_summary["Name"]
        flow_type = flow_summary.get("ContactFlowType", "CONTACT_FLOW")
        flow_state = flow_summary.get("ContactFlowState", "ACTIVE")
        flow_description = flow_summary.get("Description")

        # Get detailed contact flow content
        flow_content = self._get_contact_flow_content(instance_id, flow_id)

        return ContactFlow(
            id=flow_id,
            arn=flow_arn,
            name=flow_name,
            type=flow_type,
            state=flow_state,
            description=flow_description,
            content=flow_content,
        )

    def _get_contact_flow_content(self, instance_id: str, flow_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed content and configuration for a contact flow.

        Args:
            instance_id: The Connect instance ID
            flow_id: The contact flow ID

        Returns:
            Optional[Dict[str, Any]]: Contact flow content or None if unavailable
        """
        try:
            response = self.call_api_resilient(
                self.connect_client,
                "describe_contact_flow",
                "connect",
                InstanceId=instance_id,
                ContactFlowId=flow_id,
            )

            contact_flow_details = response.get("ContactFlow", {})
            content_string = contact_flow_details.get("Content", "{}")

            # Parse the contact flow content JSON.
            #
            # Historically this method returned the *analyzed* shape:
            # ``{"version", "start_action", "actions", "metadata",
            # "action_summary"}`` with lowercase keys. That silently
            # broke every downstream consumer that expected the raw
            # Connect document shape (``Version``, ``StartAction``,
            # ``Actions``, ``Metadata`` — capitalized). Notable
            # casualties: :class:`ContactFlowParser` (used by every
            # flow-content check under ``checks/`` and by the Caller
            # Journey Map renderer). The parser looked for ``Actions``
            # and got nothing, so it produced empty graphs — which is
            # why the Journey Map section renders empty boxes despite
            # every flow having actions.
            #
            # Now we preserve the raw contact-flow document verbatim
            # and *merge* the analyzed summary into it under the
            # ``action_summary`` key so the analyzer's own aggregate
            # stats (which read ``flow.content["action_summary"]``)
            # keep working. The parser reads ``Actions`` and ignores
            # the extra key.
            try:
                content = json.loads(content_string)
                if isinstance(content, dict):
                    content["action_summary"] = self._analyze_actions(
                        content.get("Actions", []) or []
                    )
                return content
            except json.JSONDecodeError as e:
                self.logger.warning(f"Failed to parse contact flow content for {flow_id}: {str(e)}")
                return {"raw_content": content_string, "parse_error": str(e)}

        except Exception as e:
            self.logger.warning(f"Failed to get contact flow content for {flow_id}: {str(e)}")
            raise

    # _analyze_flow_content was removed alongside the shape fix above.
    # It converted the raw contact-flow document to a lowercase-keyed
    # analyzed shape which downstream parsers/renderers/checks did not
    # understand. The remaining ``_analyze_actions`` helper is called
    # directly from ``_get_contact_flow_content`` now.

    def _analyze_actions(self, actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze contact flow actions to identify patterns and integrations.

        Args:
            actions: List of contact flow actions

        Returns:
            Dict[str, Any]: Summary of action analysis
        """
        action_types = {}
        integrations = {
            "lambda_functions": [],
            "lex_bots": [],
            "queues": [],
            "external_transfers": [],
        }
        error_handling_actions = []

        for action in actions:
            action_type = action.get("Type", "Unknown")
            action_types[action_type] = action_types.get(action_type, 0) + 1

            # Identify integrations
            if action_type == "InvokeExternalResource":
                parameters = action.get("Parameters", {})
                function_arn = parameters.get("FunctionArn")
                if function_arn:
                    integrations["lambda_functions"].append(
                        {
                            "action_id": action.get("Identifier"),
                            "function_arn": function_arn,
                        }
                    )

            elif action_type == "ConnectParticipantWithLexBot":
                parameters = action.get("Parameters", {})
                bot_name = parameters.get("BotName")
                if bot_name:
                    integrations["lex_bots"].append(
                        {
                            "action_id": action.get("Identifier"),
                            "bot_name": bot_name,
                            "bot_alias": parameters.get("BotAlias"),
                        }
                    )

            elif action_type == "TransferContactToQueue":
                parameters = action.get("Parameters", {})
                queue_id = parameters.get("QueueId")
                if queue_id:
                    integrations["queues"].append(
                        {
                            "action_id": action.get("Identifier"),
                            "queue_id": queue_id,
                        }
                    )

            elif action_type == "TransferContactToPhoneNumber":
                integrations["external_transfers"].append(
                    {
                        "action_id": action.get("Identifier"),
                        "type": "phone_transfer",
                    }
                )

            # Identify error handling
            if "Error" in action_type or "Exception" in action_type:
                error_handling_actions.append(
                    {
                        "action_id": action.get("Identifier"),
                        "type": action_type,
                    }
                )

        return {
            "total_actions": len(actions),
            "action_types": action_types,
            "integrations": integrations,
            "error_handling_actions": error_handling_actions,
            "has_error_handling": len(error_handling_actions) > 0,
            "integration_count": (
                len(integrations["lambda_functions"])
                + len(integrations["lex_bots"])
                + len(integrations["queues"])
                + len(integrations["external_transfers"])
            ),
        }

    def get_flow_summary(self, contact_flows: List[ContactFlow]) -> Dict[str, Any]:
        """
        Generate a summary of contact flow analysis results.

        Args:
            contact_flows: List of analyzed contact flows

        Returns:
            Dict[str, Any]: Summary of contact flow analysis
        """
        if not contact_flows:
            return {"total_flows": 0}

        flow_types = {}
        flow_states = {}
        total_integrations = 0
        flows_with_error_handling = 0

        for flow in contact_flows:
            # Count flow types
            flow_types[flow.type] = flow_types.get(flow.type, 0) + 1

            # Count flow states
            flow_states[flow.state] = flow_states.get(flow.state, 0) + 1

            # Analyze content if available
            if flow.content and "action_summary" in flow.content:
                action_summary = flow.content["action_summary"]
                total_integrations += action_summary.get("integration_count", 0)
                if action_summary.get("has_error_handling", False):
                    flows_with_error_handling += 1

        return {
            "total_flows": len(contact_flows),
            "flow_types": flow_types,
            "flow_states": flow_states,
            "total_integrations": total_integrations,
            "flows_with_error_handling": flows_with_error_handling,
            "error_handling_percentage": (
                (flows_with_error_handling / len(contact_flows)) * 100 if contact_flows else 0
            ),
        }
