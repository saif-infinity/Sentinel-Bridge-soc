const translations = {
  en: {
    // Navigation
    dashboard: "Dashboard",
    topology: "Topology Map",
    surveillance: "Surveillance",
    inventory: "Inventory",
    radar: "Radar Scan",
    tasks: "System Jobs",
    terminal: "SIEM Control",
    remediation: "Active Defense",
    alerts: "Terminal Alerts",
    suricata: "Network Alerts",
    network_control: "Network Control",
    network_devices: "Device Config",
    ai: "AI Copilot",
    ai_history: "AI History",
    settings: "Settings",
    rules: "Correlation Rules",
    mitre: "MITRE ATT&CK",
    cases: "Case Management",
    hunting: "Threat Hunting",
    playbooks: "Playbooks",
    admin: "Administration",
    super_admin: "Super Admin",

    // Sidebar groups
    command_center: "COMMAND CENTER",
    asset_management: "ASSET MANAGEMENT",
    terminal_ops: "TERMINAL SECURITY OPS",
    network_ops: "NETWORK SECURITY OPS",
    intelligence: "INTELLIGENCE",
    case_management: "CASE MANAGEMENT",
    automation: "AUTOMATION",
    system: "SYSTEM",

    // Dashboard
    total_threats: "Total Threats",
    critical_alerts: "Critical Alerts",
    ips_packets: "IPS Packets",
    ips_drops: "IPS Drops",
    network_presence: "Network Presence Analytics",
    realtime_bandwidth: "Real-time Bandwidth",
    ids_protection: "IDS Protection Activity",
    threat_distribution: "Threat Intensity Distribution",

    // Common
    search: "Search",
    filter: "Filter",
    loading: "Loading...",
    no_data: "No data available",
    refresh: "Refresh",
    save: "Save",
    cancel: "Cancel",
    delete: "Delete",
    edit: "Edit",
    create: "Create",
    export: "Export",
    back: "Back",
    close: "Close",
    confirm: "Confirm",
    success: "Success",
    error: "Error",
    warning: "Warning",
    info: "Info",
    retry: "Retry",

    // Auth
    login: "Login",
    logout: "Logout",
    username: "Username",
    password: "Password",
    register: "Register",
    login_title: "Sentinel Bridge",
    login_subtitle: "SOC Dashboard Access",

    // Alerts
    severity: "Severity",
    source_ip: "Source IP",
    timestamp: "Timestamp",
    description: "Description",
    agent_id: "Agent ID",
    investigate: "Investigate",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",

    // Inventory
    total_assets: "Total Assets",
    online_nodes: "Online Nodes",
    offline_nodes: "Offline Nodes",
    wazuh_agents: "Wazuh Agents",
    employee: "Employee",
    department: "Department",
    mac_address: "MAC Address",
    traffic_in: "Traffic In",
    traffic_out: "Traffic Out",

    // Terminal
    execute: "Execute",
    target: "Target",
    wazuh: "Wazuh",
    suricata: "Suricata",
    command_placeholder: "Enter command...",

    // AI
    analyze_threat: "Analyze Threat Timeline",
    generate_report: "Generate Full Network Report",
    analyzing: "Analyzing...",
    report_history: "Report History",

    // Radar
    start_scan: "Start Scan",
    scanning: "Scanning...",
    subnet: "Subnet",
    scan_type: "Scan Type",

    // Tasks
    pending: "Pending",
    running: "Running",
    success: "Success",
    failed: "Failed",
    view_result: "View Result",

    // Language
    lang_en: "English",
    lang_fr: "Francais",
  },
  fr: {
    // Navigation
    dashboard: "Tableau de Bord",
    topology: "Carte Topologie",
    surveillance: "Surveillance",
    inventory: "Inventaire",
    radar: "Scanner Radar",
    tasks: "Jobs Systeme",
    terminal: "Controle SIEM",
    remediation: "Defense Active",
    alerts: "Alertes Terminal",
    suricata: "Alertes Reseau",
    network_control: "Controle Reseau",
    network_devices: "Config Appareils",
    ai: "Copilot IA",
    ai_history: "Historique IA",
    settings: "Parametres",
    rules: "Règles de corrélation",
    mitre: "MITRE ATT&CK",
    cases: "Gestion des affaires",
    hunting: "Chasse aux menaces",
    playbooks: "Playbooks",
    admin: "Administration",
    super_admin: "Super Admin",

    // Sidebar groups
    command_center: "CENTRE DE COMMANDE",
    asset_management: "GESTION DES ASSETS",
    terminal_ops: "OPS SECURITE TERMINAL",
    network_ops: "OPS SECURITE RESEAU",
    intelligence: "INTELLIGENCE",
    case_management: "GESTION DES AFFAIRES",
    automation: "AUTOMATION",
    system: "SYSTEME",

    // Dashboard
    total_threats: "Menaces Totales",
    critical_alerts: "Alertes Critiques",
    ips_packets: "Paquets IPS",
    ips_drops: "Drops IPS",
    network_presence: "Analyse de Presence Reseau",
    realtime_bandwidth: "Bande Passante Temps Reel",
    ids_protection: "Activite Protection IDS",
    threat_distribution: "Distribution Intensite Menaces",

    // Common
    search: "Rechercher",
    filter: "Filtrer",
    loading: "Chargement...",
    no_data: "Aucune donnee disponible",
    refresh: "Actualiser",
    save: "Enregistrer",
    cancel: "Annuler",
    delete: "Supprimer",
    edit: "Modifier",
    create: "Creer",
    export: "Exporter",
    back: "Retour",
    close: "Fermer",
    confirm: "Confirmer",
    success: "Succes",
    error: "Erreur",
    warning: "Attention",
    info: "Info",

    // Auth
    login: "Connexion",
    logout: "Deconnexion",
    username: "Nom d'utilisateur",
    password: "Mot de passe",
    register: "S'inscrire",
    login_title: "Sentinel Bridge",
    login_subtitle: "Acces SOC Dashboard",

    // Alerts
    severity: "Severite",
    source_ip: "IP Source",
    timestamp: "Horodatage",
    description: "Description",
    agent_id: "ID Agent",
    investigate: "Investiguer",
    critical: "Critique",
    high: "Eleve",
    medium: "Moyen",
    low: "Faible",

    // Inventory
    total_assets: "Total Assets",
    online_nodes: "Noeuds En Ligne",
    offline_nodes: "Noeuds Hors Ligne",
    wazuh_agents: "Agents Wazuh",
    employee: "Employe",
    department: "Departement",
    mac_address: "Adresse MAC",
    traffic_in: "Traffic Entree",
    traffic_out: "Traffic Sortie",

    // Terminal
    execute: "Executer",
    target: "Cible",
    wazuh: "Wazuh",
    suricata: "Suricata",
    command_placeholder: "Entrer commande...",

    // AI
    analyze_threat: "Analyser Timeline Menaces",
    generate_report: "Generer Rapport Reseau Global",
    analyzing: "Analyse en cours...",
    report_history: "Historique des Rapports",

    // Radar
    start_scan: "Lancer Scan",
    scanning: "Scan en cours...",
    subnet: "Sous-reseau",
    scan_type: "Type de Scan",

    // Tasks
    pending: "En attente",
    running: "En cours",
    success: "Reussi",
    failed: "Echoue",
    view_result: "Voir Resultat",

    // Language
    lang_en: "English",
    lang_fr: "Francais",
  },
};

export default translations;
