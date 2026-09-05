// Report Interactive Features
class AssessmentReportController {
    constructor() {
        this.findings = [];
        this.filteredFindings = [];
        this.currentFilters = {
            severity: 'all',
            status: 'all',
            pillar: 'all',
            instance: 'all',
            search: ''
        };
        this.darkMode = false;
        this.severityChart = null;
        this.pillarChart = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupTabNavigation();
        this.loadFindings();
        this.initializeFiltersFromControls();
        this.setupDarkModeToggle();
        this.initializeCharts();
        this.applyFilters();
        this.setupCollapsibleSections();
        this.setupCopyButtons();
        this.setupExportButtons();
    }

    initializeFiltersFromControls() {
        const severityFilter = document.getElementById('severity-filter');
        const statusFilter = document.getElementById('status-filter');
        const pillarFilter = document.getElementById('pillar-filter');
        const instanceFilter = document.getElementById('instance-filter');
        const searchInput = document.getElementById('search-input');

        this.currentFilters.severity = severityFilter ? severityFilter.value : 'all';
        this.currentFilters.status = statusFilter ? statusFilter.value : 'all';
        this.currentFilters.pillar = pillarFilter ? pillarFilter.value : 'all';
        this.currentFilters.instance = instanceFilter ? instanceFilter.value : 'all';
        this.currentFilters.search = searchInput ? searchInput.value.toLowerCase() : '';
    }

    setupTabNavigation() {
        // Initialize pillar tabs
        const tabButtons = document.querySelectorAll('.pillar-tab');
        const tabContents = document.querySelectorAll('.pillar-tab-content');

        // Set first tab as active by default
        if (tabButtons.length > 0) {
            tabButtons[0].classList.add('active');
        }
        if (tabContents.length > 0) {
            tabContents[0].classList.add('active');
        }

        // Add click event listeners to tab buttons
        tabButtons.forEach((button, index) => {
            button.addEventListener('click', () => {
                // Remove active class from all tabs and contents
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));

                // Add active class to clicked tab and corresponding content
                button.classList.add('active');
                if (tabContents[index]) {
                    tabContents[index].classList.add('active');
                }

                // Sync with pillar filter dropdown
                const pillarName = button.dataset.pillar;
                if (pillarName) {
                    this.syncPillarFilter(pillarName);
                }

                // Update filters if needed
                this.applyFilters();
            });
        });
    }

    syncPillarTab(pillarValue) {
        // Sync the tab navigation when pillar filter changes
        const tabButtons = document.querySelectorAll('.pillar-tab');
        const tabContents = document.querySelectorAll('.pillar-tab-content');

        if (pillarValue === 'all') {
            // Show first tab when "all" is selected
            if (tabButtons.length > 0) {
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));
                tabButtons[0].classList.add('active');
                tabContents[0].classList.add('active');
            }
        } else {
            // Find and activate the matching tab
            tabButtons.forEach((button, index) => {
                const pillarName = button.dataset.pillar;
                if (pillarName === pillarValue) {
                    tabButtons.forEach(btn => btn.classList.remove('active'));
                    tabContents.forEach(content => content.classList.remove('active'));
                    button.classList.add('active');
                    if (tabContents[index]) {
                        tabContents[index].classList.add('active');
                    }
                }
            });
        }
    }

    syncPillarFilter(pillarName) {
        // Sync the pillar filter dropdown when tab is clicked
        const pillarFilter = document.getElementById('pillar-filter');
        if (pillarFilter && pillarName) {
            pillarFilter.value = pillarName;
            this.currentFilters.pillar = pillarName;
        }
    }

    setupDarkModeToggle() {
        // Check for saved preference or system preference
        const savedPreference = localStorage.getItem('darkMode');
        const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

        if (savedPreference !== null) {
            this.darkMode = savedPreference === 'true';
        } else {
            this.darkMode = systemPrefersDark;
        }

        // Apply initial dark mode
        document.body.classList.toggle('dark-mode', this.darkMode);

        // Add dark mode toggle button
        const header = document.querySelector('.report-header');
        if (header) {
            // Check if toggle already exists
            let toggleButton = document.querySelector('.dark-mode-toggle');
            if (!toggleButton) {
                toggleButton = document.createElement('button');
                toggleButton.className = 'dark-mode-toggle';
                toggleButton.setAttribute('aria-label', 'Toggle dark mode');
                header.appendChild(toggleButton);
            }

            // Set initial icon using textContent for safety
            const icon = document.createElement('i');
            icon.className = this.darkMode ? 'fas fa-sun' : 'fas fa-moon';
            toggleButton.textContent = '';
            toggleButton.appendChild(icon);

            toggleButton.addEventListener('click', () => {
                this.toggleDarkMode();
            });
        }
    }

    toggleDarkMode() {
        this.darkMode = !this.darkMode;
        document.body.classList.toggle('dark-mode', this.darkMode);

        // Update toggle button icon
        const toggleButton = document.querySelector('.dark-mode-toggle');
        if (toggleButton) {
            const icon = document.createElement('i');
            icon.className = this.darkMode ? 'fas fa-sun' : 'fas fa-moon';
            toggleButton.textContent = '';
            toggleButton.appendChild(icon);
        }

        // Store preference in localStorage
        localStorage.setItem('darkMode', this.darkMode.toString());
        this.updateThemeAwareCharts();
    }

    setupCollapsibleSections() {
        // Add collapsible functionality to remediation sections
        const remediationSections = document.querySelectorAll('.finding-remediation');
        remediationSections.forEach(section => {
            const title = section.querySelector('.remediation-title');
            if (title) {
                // Add chevron icon
                if (!title.querySelector('.chevron')) {
                    const chevron = document.createElement('i');
                    chevron.className = 'fas fa-chevron-down chevron';
                    chevron.style.marginLeft = 'auto';
                    chevron.style.transition = 'transform 0.3s ease';
                    title.appendChild(chevron);
                }

                title.style.cursor = 'pointer';
                title.style.display = 'flex';
                title.style.alignItems = 'center';

                title.addEventListener('click', () => {
                    const content = section.querySelector('p');
                    const chevron = title.querySelector('.chevron');
                    if (content && chevron) {
                        const isHidden = content.style.display === 'none';
                        content.style.display = isHidden ? 'block' : 'none';
                        chevron.style.transform = isHidden ? 'rotate(0deg)' : 'rotate(180deg)';
                    }
                });
            }
        });

        // Add collapsible functionality to evidence sections
        const evidenceSections = document.querySelectorAll('.finding-evidence');
        evidenceSections.forEach(section => {
            const title = section.querySelector('h4, h5');
            if (title) {
                // Wrap content in a container
                const content = section.querySelector('pre');
                if (content && !content.parentElement.classList.contains('finding-evidence-content')) {
                    const contentWrapper = document.createElement('div');
                    contentWrapper.className = 'finding-evidence-content';
                    content.parentNode.insertBefore(contentWrapper, content);
                    contentWrapper.appendChild(content);
                }

                // Make title clickable
                title.style.cursor = 'pointer';

                title.addEventListener('click', () => {
                    section.classList.toggle('collapsed');
                });
            }
        });
    }

    setupCopyButtons() {
        // Add copy buttons to code blocks
        const codeBlocks = document.querySelectorAll('pre code');
        codeBlocks.forEach((codeBlock, index) => {
            const pre = codeBlock.parentElement;
            if (!pre.querySelector('.copy-btn')) {
                const copyBtn = document.createElement('button');
                copyBtn.className = 'copy-btn';
                copyBtn.setAttribute('aria-label', 'Copy to clipboard');

                // Create icon element safely
                const icon = document.createElement('i');
                icon.className = 'fas fa-copy';
                copyBtn.appendChild(icon);

                copyBtn.style.cssText = `
                    position: absolute;
                    top: 0.5rem;
                    right: 0.5rem;
                    background: rgba(255, 255, 255, 0.8);
                    border: 1px solid var(--gray-300);
                    border-radius: var(--radius-md);
                    padding: 0.25rem 0.5rem;
                    cursor: pointer;
                    font-size: 0.75rem;
                    transition: all 0.2s ease;
                    z-index: 10;
                `;

                // Dark mode styles
                if (this.darkMode) {
                    copyBtn.style.background = 'rgba(30, 41, 59, 0.8)';
                    copyBtn.style.border = '1px solid var(--dark-border)';
                }

                copyBtn.addEventListener('click', () => {
                    this.copyToClipboard(codeBlock.textContent, copyBtn);
                });

                pre.style.position = 'relative';
                pre.appendChild(copyBtn);
            }
        });
    }

    setupExportButtons() {
        // Add export buttons to findings
        const findings = document.querySelectorAll('.finding-card');
        findings.forEach(finding => {
            const header = finding.querySelector('.finding-header');
            if (header && !header.querySelector('.export-finding-btn')) {
                const exportBtn = document.createElement('button');
                exportBtn.className = 'export-finding-btn';
                exportBtn.setAttribute('aria-label', 'Export finding');

                // Create icon element safely
                const icon = document.createElement('i');
                icon.className = 'fas fa-download';
                exportBtn.appendChild(icon);

                exportBtn.style.cssText = `
                    background: transparent;
                    border: none;
                    color: var(--gray-500);
                    cursor: pointer;
                    font-size: 0.875rem;
                    margin-left: 0.5rem;
                    transition: all 0.2s ease;
                `;

                exportBtn.addEventListener('click', () => {
                    this.exportFinding(finding);
                });

                const badgesContainer = header.querySelector('.finding-badges');
                if (badgesContainer) {
                    badgesContainer.appendChild(exportBtn);
                }
            }
        });
    }

    setupEventListeners() {
        // Filter controls
        const severityFilter = document.getElementById('severity-filter');
        const statusFilter = document.getElementById('status-filter');
        const pillarFilter = document.getElementById('pillar-filter');
        const instanceFilter = document.getElementById('instance-filter');
        const searchInput = document.getElementById('search-input');
        const clearFiltersBtn = document.getElementById('clear-filters');
        const exportBtn = document.getElementById('export-data');

        if (severityFilter) {
            severityFilter.addEventListener('change', (e) => {
                this.currentFilters.severity = e.target.value;
                this.applyFilters();
            });
        }

        if (statusFilter) {
            statusFilter.addEventListener('change', (e) => {
                this.currentFilters.status = e.target.value;
                this.applyFilters();
            });
        }

        if (pillarFilter) {
            pillarFilter.addEventListener('change', (e) => {
                this.currentFilters.pillar = e.target.value;
                this.applyFilters();
                // Sync with tab navigation
                this.syncPillarTab(e.target.value);
            });
        }

        if (instanceFilter) {
            instanceFilter.addEventListener('change', (e) => {
                this.currentFilters.instance = e.target.value;
                this.applyFilters();
            });
        }

        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.currentFilters.search = e.target.value.toLowerCase();
                this.applyFilters();
            });
        }

        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', () => {
                this.clearFilters();
            });
        }

        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportData();
            });
        }
    }

    loadFindings() {
        // Load findings from data attributes or embedded JSON
        const findingElements = document.querySelectorAll('.finding-card');
        this.findings = Array.from(findingElements).map(element => ({
            element: element,
            severity: element.dataset.severity,
            status: element.dataset.status,
            pillar: element.dataset.pillar,
            instance: element.dataset.instance || '',
            title: element.dataset.title || '',
            description: element.dataset.description || '',
            remediation: element.dataset.remediation || '',
            evidence: element.dataset.evidence || ''
        }));
    }

    applyFilters() {
        this.filteredFindings = this.findings.filter(finding => {
            // Severity filter
            if (this.currentFilters.severity !== 'all' &&
                finding.severity !== this.currentFilters.severity) {
                return false;
            }

            // Status filter
            if (this.currentFilters.status !== 'all' &&
                finding.status !== this.currentFilters.status) {
                return false;
            }

            // Pillar filter
            if (this.currentFilters.pillar !== 'all' &&
                finding.pillar !== this.currentFilters.pillar) {
                return false;
            }

            // Instance filter
            if (this.currentFilters.instance !== 'all' &&
                finding.instance !== this.currentFilters.instance) {
                return false;
            }

            // Search filter
            const searchTerm = this.currentFilters.search;
            if (searchTerm &&
                !finding.title.toLowerCase().includes(searchTerm) &&
                !finding.description.toLowerCase().includes(searchTerm) &&
                !finding.remediation.toLowerCase().includes(searchTerm) &&
                !finding.evidence.toLowerCase().includes(searchTerm)) {
                return false;
            }

            return true;
        });

        this.updateDisplay();
        this.ensureActivePillarHasResults();
        this.updateFilterStats();
    }

    updateDisplay() {
        // Show/hide findings based on filters
        this.findings.forEach(finding => {
            const isVisible = this.filteredFindings.includes(finding);
            finding.element.style.display = isVisible ? 'block' : 'none';
        });

        // Update pillar sections visibility
        this.updatePillarSections();

        // Update pillar tab badges
        this.updatePillarTabBadges();
    }

    updatePillarTabBadges() {
        // Count findings per pillar based on current filters
        const pillarCounts = {};

        this.filteredFindings.forEach(finding => {
            const pillar = finding.pillar;
            if (pillar) {
                pillarCounts[pillar] = (pillarCounts[pillar] || 0) + 1;
            }
        });

        // Update badge numbers in tabs
        const tabButtons = document.querySelectorAll('.pillar-tab');
        tabButtons.forEach(button => {
            const pillarName = button.dataset.pillar;
            const badge = button.querySelector('.pillar-tab-badge');

            if (badge && pillarName) {
                const count = pillarCounts[pillarName] || 0;
                badge.textContent = count;

                // Optionally hide badge if count is 0
                badge.style.display = count > 0 ? 'inline-flex' : 'none';
            }
        });
    }

    ensureActivePillarHasResults() {
        const tabButtons = Array.from(document.querySelectorAll('.pillar-tab'));
        const activeTab = tabButtons.find(button => button.classList.contains('active'));
        const activeCount = activeTab
            ? Number(activeTab.querySelector('.pillar-tab-badge')?.textContent || 0)
            : 0;

        if (activeCount > 0) return;

        const firstTabWithResults = tabButtons.find(button => {
            const badge = button.querySelector('.pillar-tab-badge');
            return Number(badge?.textContent || 0) > 0;
        });

        if (firstTabWithResults?.dataset.pillar) {
            this.syncPillarTab(firstTabWithResults.dataset.pillar);
        }
    }

    updatePillarSections() {
        const pillarSections = document.querySelectorAll('.pillar-section');
        pillarSections.forEach(section => {
            const visibleFindings = section.querySelectorAll('.finding-card:not([style*="display: none"])');
            section.style.display = visibleFindings.length > 0 ? 'block' : 'none';
        });
    }

    updateFilterStats() {
        const statsElement = document.getElementById('filter-stats');
        if (statsElement) {
            const total = this.findings.length;
            const visible = this.filteredFindings.length;
            const percentage = total > 0 ? Math.round((visible / total) * 100) : 0;

            // Clear existing content
            statsElement.textContent = '';

            // Create elements safely without innerHTML
            const showingText = document.createTextNode('Showing ');
            const visibleStrong = document.createElement('strong');
            visibleStrong.textContent = visible;
            const ofText = document.createTextNode(' of ');
            const totalStrong = document.createElement('strong');
            totalStrong.textContent = total;
            const findingsText = document.createTextNode(' findings ');

            const percentSpan = document.createElement('span');
            percentSpan.className = 'filter-stats-match';
            percentSpan.textContent = `(${percentage}% match)`;

            statsElement.appendChild(showingText);
            statsElement.appendChild(visibleStrong);
            statsElement.appendChild(ofText);
            statsElement.appendChild(totalStrong);
            statsElement.appendChild(findingsText);
            statsElement.appendChild(percentSpan);
        }
    }

    clearFilters() {
        this.currentFilters = {
            severity: 'all',
            status: 'all',
            pillar: 'all',
            instance: 'all',
            search: ''
        };

        // Reset form controls
        const severityFilter = document.getElementById('severity-filter');
        const statusFilter = document.getElementById('status-filter');
        const pillarFilter = document.getElementById('pillar-filter');
        const instanceFilter = document.getElementById('instance-filter');
        const searchInput = document.getElementById('search-input');

        if (severityFilter) severityFilter.value = 'all';
        if (statusFilter) statusFilter.value = 'all';
        if (pillarFilter) pillarFilter.value = 'all';
        if (instanceFilter) instanceFilter.value = 'all';
        if (searchInput) searchInput.value = '';

        this.applyFilters();
    }

    exportData() {
        // Export filtered findings as JSON
        const exportData = {
            timestamp: new Date().toISOString(),
            filters: this.currentFilters,
            summary: {
                total_findings: this.findings.length,
                visible_findings: this.filteredFindings.length,
                filter_percentage: this.findings.length > 0 ?
                    Math.round((this.filteredFindings.length / this.findings.length) * 100) : 0
            },
            findings: this.filteredFindings.map(f => ({
                severity: f.severity,
                status: f.status,
                pillar: f.pillar,
                title: f.title,
                description: f.description,
                resource_id: f.instance,
                remediation: f.remediation,
                evidence: f.evidence
            }))
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], {
            type: 'application/json'
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `assessment-findings-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        // Show success message
        this.showToast('Findings exported successfully!', 'success');
    }

    exportFinding(findingElement) {
        // Export a single finding as JSON
        const findingData = {
            severity: findingElement.dataset.severity,
            status: findingElement.dataset.status,
            pillar: findingElement.dataset.pillar,
            title: findingElement.dataset.title,
            description: findingElement.dataset.description,
            resource_id: findingElement.dataset.instance,
            remediation: findingElement.dataset.remediation,
            evidence: findingElement.dataset.evidence,
            timestamp: new Date().toISOString()
        };

        const blob = new Blob([JSON.stringify(findingData, null, 2)], {
            type: 'application/json'
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `finding-${findingData.title.replace(/\s+/g, '-').toLowerCase()}-${new Date().getTime()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        // Show success message
        this.showToast('Finding exported successfully!', 'success');
    }

    copyToClipboard(text, button) {
        navigator.clipboard.writeText(text).then(() => {
            // Show success feedback
            const originalIcon = button.querySelector('i');
            const originalClassName = originalIcon ? originalIcon.className : '';

            // Replace icon with check mark
            button.textContent = '';
            const checkIcon = document.createElement('i');
            checkIcon.className = 'fas fa-check';
            button.appendChild(checkIcon);

            button.style.background = 'rgba(34, 197, 94, 0.2)';
            button.style.borderColor = 'var(--success-500)';

            setTimeout(() => {
                // Restore original icon
                button.textContent = '';
                const restoreIcon = document.createElement('i');
                restoreIcon.className = originalClassName;
                button.appendChild(restoreIcon);

                button.style.background = '';
                button.style.borderColor = '';
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy: ', err);
            this.showToast('Failed to copy to clipboard', 'error');
        });
    }

    showToast(message, type = 'info') {
        // Create toast notification
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;

        // Apply CSS variables for styling
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-lg);
            z-index: var(--z-toast);
            animation: slideInRight 0.3s ease, fadeOut 0.3s ease 2.7s forwards;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        `;

        document.body.appendChild(toast);

        // Remove toast after animation
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 3000);
    }

    initializeCharts() {
        // Initialize Chart.js charts with improved loading check
        if (typeof Chart !== 'undefined') {
            console.log('Chart.js loaded successfully, initializing charts...');
            this.createStatusChart();
            this.createSeverityChart();
            this.createPillarChart();
        } else {
            console.log('Chart.js not available, charts will not be displayed');
            const chartContainers = document.querySelectorAll('.chart-container');
            chartContainers.forEach(container => {
                container.textContent = '';
                const fallback = document.createElement('div');
                fallback.style.cssText = 'display: flex; align-items: center; justify-content: center; height: 300px; color: #666; font-style: italic;';
                fallback.textContent = 'Chart library not available';
                container.appendChild(fallback);
            });
        }
    }

    createStatusChart() {
        const ctx = document.getElementById('status-chart');
        if (!ctx) return;

        try {
            const chartDataElement = document.getElementById('chart-data');
            if (!chartDataElement) {
                console.error('Chart data element not found');
                return;
            }

            const allChartData = JSON.parse(chartDataElement.textContent);
            const data = allChartData.status_distribution;
            console.log('Status chart data:', data);

            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: data.labels || [],
                    datasets: [{
                        data: data.data || [],
                        backgroundColor: data.colors || [],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
            console.log('Status chart initialized successfully');
        } catch (e) {
            console.error('Error initializing status chart:', e);
        }
    }

    getThemeAwareChartColors() {
        const isDark = document.body.classList.contains('dark-mode');
        return {
            text: isDark ? '#e9ecef' : '#5f6b7a',
            grid: isDark ? 'rgba(233, 236, 239, 0.18)' : 'rgba(95, 107, 122, 0.18)'
        };
    }

    updateThemeAwareCharts() {
        const theme = this.getThemeAwareChartColors();
        [this.severityChart, this.pillarChart].forEach(chart => {
            if (!chart) return;

            Object.values(chart.options.scales || {}).forEach(axis => {
                if (axis.ticks) axis.ticks.color = theme.text;
                if (axis.grid) axis.grid.color = theme.grid;
            });

            const legend = chart.options.plugins?.legend;
            if (legend) {
                legend.labels = legend.labels || {};
                legend.labels.color = theme.text;
            }
            chart.update('none');
        });
    }

    createSeverityChart() {
        const ctx = document.getElementById('severity-chart');
        if (!ctx) return;

        try {
            const chartDataElement = document.getElementById('chart-data');
            if (!chartDataElement) {
                console.error('Chart data element not found');
                return;
            }

            const allChartData = JSON.parse(chartDataElement.textContent);
            const data = allChartData.severity_distribution;
            const theme = this.getThemeAwareChartColors();
            console.log('Severity chart data:', data);

            this.severityChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: data.labels || [],
                    datasets: [{
                        label: 'Failed Findings',
                        data: data.data || [],
                        backgroundColor: data.colors || [],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            ticks: { color: theme.text },
                            grid: { color: theme.grid }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1,
                                color: theme.text
                            },
                            grid: { color: theme.grid }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false,
                            labels: { color: theme.text }
                        }
                    }
                }
            });
            console.log('Severity chart initialized successfully');
        } catch (e) {
            console.error('Error initializing severity chart:', e);
        }
    }

    createPillarChart() {
        const ctx = document.getElementById('pillar-chart');
        if (!ctx) return;

        try {
            const chartDataElement = document.getElementById('chart-data');
            if (!chartDataElement) {
                console.error('Chart data element not found');
                return;
            }

            const allChartData = JSON.parse(chartDataElement.textContent);
            const data = allChartData.pillar_breakdown;
            const theme = this.getThemeAwareChartColors();
            console.log('Pillar chart data:', data);

            const labels = Object.keys(data);
            const passedData = labels.map(label => data[label].passed);
            const failedData = labels.map(label => data[label].failed);

            this.pillarChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels.map(l => l.replace('_', ' ').toUpperCase()),
                    datasets: [
                        {
                            label: 'Passed',
                            data: passedData,
                            backgroundColor: '#28a745',
                            borderWidth: 1
                        },
                        {
                            label: 'Failed',
                            data: failedData,
                            backgroundColor: '#dc3545',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            stacked: true,
                            ticks: { color: theme.text },
                            grid: { color: theme.grid }
                        },
                        y: {
                            stacked: true,
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1,
                                color: theme.text
                            },
                            grid: { color: theme.grid }
                        }
                    },
                    plugins: {
                        legend: {
                            labels: { color: theme.text }
                        }
                    }
                }
            });
            console.log('Pillar chart initialized successfully');
        } catch (e) {
            console.error('Error initializing pillar chart:', e);
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    window.assessmentReportController = new AssessmentReportController();
});

// Utility functions
function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.style.display = section.style.display === 'none' ? 'block' : 'none';
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show success message
        const toast = document.createElement('div');
        toast.textContent = 'Copied to clipboard!';
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 0.75rem 1rem;
            border-radius: 4px;
            z-index: 1000;
            animation: slideIn 0.3s ease;
        `;
        document.body.appendChild(toast);
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 3000);
    });
}