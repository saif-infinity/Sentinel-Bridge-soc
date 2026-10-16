(() => {
  "use strict";

  // Read-only documentation. These controls never call the backend or execute a job.
  // Keep the explanations aligned with ARCHITECTURE.md and the source references.
  const codeRoot =
    "https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/blob/arena/fc0f72da-projet-soc-ips-siem-xdr/";
  const pages = {
    apercu: {
      label: "Vue d’ensemble",
      title: "Une vision d’ensemble.",
      description:
        "La nature du projet, ses acteurs et le lien entre ses briques.",
    },
    architecture: {
      label: "Architecture",
      title: "Les composants, en interaction.",
      description:
        "Du navigateur aux workers : comprendre qui fait quoi, et dans quel processus.",
    },
    parcours: {
      label: "Parcours d’un signal",
      title: "Un signal. Plusieurs chemins.",
      description:
        "Explorer chaque étape : entrée, traitement, sortie et avantage attendu.",
    },
    avantages: {
      label: "Avantages & limites",
      title: "Des mécanismes. Des apports concrets.",
      description:
        "Relier les problèmes SOC à leurs réponses techniques, sans masquer les limites.",
    },
  };

  const components = {
    soc: {
      title: "Interface SOC",
      kind: "INTERFACE / REACT",
      description:
        "L’espace de travail de l’analyste : alertes, investigations, règles, dossiers et résultats.",
      input: "Réponses HTTP et mises à jour WebSocket du backend.",
      output:
        "Requêtes de lecture et opérations autorisées par les rôles et scopes.",
      caution:
        "L’interface ne remplace pas les contrôles d’accès de l’API. Les deux frontends restent distincts.",
      code: ["frontend/package.json", "frontend/src/lib/formatters.js"],
    },
    admin: {
      title: "Console admin",
      kind: "INTERFACE / REACT",
      description:
        "Une application distincte pour l’administration des accès, demandes, paramètres et capteurs.",
      input:
        "État des demandes et données d’administration exposées par l’API.",
      output: "Décisions et opérations d’un opérateur autorisé.",
      caution:
        "Elle ne partage pas un mécanisme d’authentification unique avec l’interface SOC. Ne pas déduire les droits du seul écran.",
      code: [
        "admin-frontend/package.json",
        "backend/app/interface/api/admin.py",
      ],
    },
    wazuh: {
      title: "Wazuh",
      kind: "SERVICE EXTERNE / À CONNECTER",
      description:
        "Source d’alertes et de contexte hôte, également utilisée par certaines actions de réponse.",
      input:
        "Credentials, activation de la source et configuration du manager / indexer.",
      output:
        "Alertes reçues par webhook ou synchronisation ; contexte hôte selon le collecteur.",
      caution:
        "La source doit être activée et joignable. Une réponse HTTP ignored ou error n’est pas une alerte acceptée.",
      code: [
        "backend/app/interface/api/webhooks.py",
        "backend/app/infrastructure/wazuh/client.py",
      ],
    },
    suricata: {
      title: "Suricata",
      kind: "SONDE EXTERNE / À CONNECTER",
      description:
        "Fournit des événements réseau EVE JSON / NDJSON qui sont adaptés au pipeline commun.",
      input: "Événements d’une sonde et credentials du webhook configuré.",
      output:
        "Payload canonique, sévérité normalisée et alertes acceptées selon le pipeline.",
      caution:
        "La sévérité brute 1 est la plus grave. Aucun blocage Suricata inline n’est implémenté ici.",
      code: [
        "backend/app/interface/api/suricata.py",
        "backend/app/application/normalization.py",
      ],
    },
    api: {
      title: "Interfaces & contrôles",
      kind: "PROCESSUS API / FASTAPI",
      description:
        "Expose les routes, valide les requêtes et applique les mécanismes d’accès prévus par chaque chemin.",
      input:
        "Requêtes des interfaces et webhooks ; credentials et contexte tenant.",
      output: "Appels aux cas d’usage et réponses HTTP / WebSocket.",
      caution:
        "Plusieurs mécanismes d’authentification coexistent. Les guards et filtres tenant doivent être vérifiés pour chaque nouveau parcours.",
      code: ["backend/app/interface/main.py", "backend/app/core/rbac.py"],
    },
    pipeline: {
      title: "Pipeline & détection",
      kind: "APPLICATION / CHEMIN SYNCHRONE",
      description:
        "Transforme un signal reçu en donnée exploitable, puis évalue les règles pour les événements acceptés.",
      input:
        "Payload d’ingestion : source, tenant, temps, IP, signature et sévérité.",
      output:
        "accepted, deduped ou suppressed ; correspondances de règles si disponibles.",
      caution:
        "La TI optionnelle précède la déduplication. Le tracker est en mémoire du processus et son empreinte n’inclut pas le tenant.",
      code: [
        "backend/app/application/pipeline.py",
        "backend/app/application/rules/engine.py",
      ],
    },
    bus: {
      title: "Bus & modules métier",
      kind: "APPLICATION / ÉVÉNEMENTS LOCAUX",
      description:
        "Relie les correspondances de règles aux handlers d’investigation et de SOAR. Les modules sont aussi utilisés côté worker selon le parcours.",
      input:
        "RuleMatchEvent et handlers enregistrés dans le processus courant.",
      output:
        "Tentative de persistance dans l’outbox, dispatch local et déclenchements sous conditions.",
      caution:
        "Bus local ≠ outbox SQL ≠ Redis. Un échec d’écriture de l’outbox n’empêche pas à lui seul le dispatch local : pas de garantie exactly once.",
      code: [
        "backend/app/application/events.py",
        "backend/app/application/soar/executor.py",
      ],
    },
    postgres: {
      title: "PostgreSQL",
      kind: "PERSISTANCE / TIMESCALEDB",
      description:
        "Conserve les objets métier et l’outbox. L’API et les workers accèdent à la base selon leurs cas d’usage.",
      input: "Écritures et lectures SQLAlchemy ; migrations Alembic.",
      output:
        "Alertes, cases, règles, preuves, recommandations, runs et rapports persistés.",
      caution:
        "SQLite existe pour des environnements de test. Un enregistrement en base ne rend pas un effet externe transactionnel ou réversible.",
      code: ["backend/app/core/db.py", "backend/app/domain/models.py"],
    },
    redis: {
      title: "Redis",
      kind: "BROKER / STREAMS / ÉTATS TECHNIQUES",
      description:
        "Transporte les jobs Celery et les messages syslog ; intervient également dans des mécanismes de rate-limit et de cache.",
      input: "Messages de tâches et événements publiés dans Redis Streams.",
      output:
        "Travaux destinés aux consommateurs configurés et résultats selon le parcours.",
      caution:
        "Une publication n’est pas une exécution confirmée. Le bus Python local et l’outbox SQL ne sont pas ce broker Redis.",
      code: [
        "backend/app/core/celery.py",
        "backend/app/infrastructure/syslog/stream.py",
      ],
    },
    celery: {
      title: "Celery & Beat",
      kind: "PROCESSUS WORKER / SCHEDULER",
      description:
        "Le worker exécute les tâches enregistrées. Beat déclenche les travaux périodiques planifiés.",
      input: "Tâches sur les files celery et investigation, selon les jobs.",
      output:
        "Investigations, réponses, notifications, rapports et travaux de maintenance selon activation.",
      caution:
        "Le worker doit écouter la file investigation. Les playbooks SOAR directs utilisent des threads locaux ; ils ne deviennent pas des jobs Celery par simple présence de Redis.",
      code: [
        "backend/app/core/celery.py",
        "backend/app/infrastructure/jobs/investigation_tasks.py",
      ],
    },
    syslog: {
      title: "Syslog séparé",
      kind: "RÉCEPTEUR AUTONOME / TCP & UDP",
      description:
        "Un processus séparé reçoit les messages, résout leur tenant par mapping d’IP et publie dans un Redis Stream.",
      input: "Messages réseau sur le port configuré, 1514 par défaut.",
      output:
        "Événements du Stream lus par jobs.syslog.process_batch, puis transmis au pipeline.",
      caution:
        "Le consommateur doit être déclenché : il n’a pas de planification Beat dédiée. Le récepteur n’offre pas une authentification JWT ou un service syslog TLS complet.",
      code: [
        "backend/app/infrastructure/syslog/server.py",
        "backend/app/infrastructure/jobs/syslog_process.py",
      ],
    },
    ti: {
      title: "Threat Intelligence",
      kind: "INTÉGRATION OPTIONNELLE / CONTEXTE IOC",
      description:
        "Recherche du contexte sur une IP via le client TI et son cache, notamment avec AbuseIPDB.",
      input: "IP, flag d’activation et configuration / clé du fournisseur.",
      output:
        "Verdict et score utilisables pour enrichir le signal ou une investigation.",
      caution:
        "unknown ne signifie pas clean. Une erreur TI dans ingest_alert n’interrompt pas automatiquement le pipeline.",
      code: [
        "backend/app/infrastructure/threat_intel/client.py",
        "backend/app/application/pipeline.py",
      ],
    },
    ia: {
      title: "Assistance IA",
      kind: "INTÉGRATION OPTIONNELLE / OLLAMA & HF",
      description:
        "Assiste certains parcours d’analyse et de synthèse. L’investigation peut utiliser un template de repli.",
      input: "Contexte et preuves disponibles ; modèle et service configurés.",
      output:
        "Synthèse ou assistance à relire, et marqueurs de complétion selon le parcours.",
      caution:
        "Une synthèse n’est pas une preuve nouvelle. Sans réponse LLM, le fallback peut marquer une complétion partielle.",
      code: [
        "backend/app/application/investigations/llm.py",
        "backend/app/application/investigations/summaries.py",
      ],
    },
    actions: {
      title: "Actions & notifications",
      kind: "CONNECTEURS / SOUS CONDITIONS",
      description:
        "Appelle les connecteurs implémentés et les canaux configurés, avec une politique d’approbation selon l’action.",
      input: "Run autorisé, cible, paramètres, credentials et canal configuré.",
      output:
        "Résultats et erreurs des étapes ou du transport, à confronter à l’effet réel.",
      caution:
        "push-config réseau reste un dry-run. Un succès de dispatch ou une trace notify n’est pas une preuve de blocage ou de livraison.",
      code: [
        "backend/app/application/response/actions.py",
        "backend/app/application/reporting/delivery.py",
      ],
    },
  };

  const steps = [
    {
      title: "Collecter le signal",
      executor: "HTTP / récepteur syslog",
      summary:
        "Identifier l’origine et le canal d’entrée avant de parler d’alerte acceptée.",
      inputTitle: "Événement source",
      input:
        "Webhook Wazuh, EVE Suricata, message syslog ou injection de laboratoire autorisée.",
      processTitle: "Vérifier le chemin d’entrée",
      process: [
        "Contrôler les credentials et l’activation sur les webhooks.",
        "Décoder le payload ; parser le message syslog et résoudre son tenant.",
        "Pour syslog, publier en Stream puis déclencher le consommateur.",
      ],
      outputTitle: "Payload reçu ou refusé",
      output:
        "Transmission au pipeline, état ignored, refus ou erreur selon le chemin. Une réponse HTTP seule ne prouve pas l’ingestion.",
      benefit:
        "Réunir plusieurs sources dans un parcours dont l’origine et les points d’entrée restent explicables.",
      guard:
        "La source doit être activée. Le récepteur syslog est séparé, sans JWT équivalent ni TLS intégré complet ; son réseau et ses mappings doivent être protégés.",
      code: [
        "backend/app/interface/api/webhooks.py",
        "backend/app/infrastructure/jobs/syslog_process.py",
      ],
    },
    {
      title: "Structurer les formats",
      executor: "Adaptateurs + pipeline",
      summary:
        "Faire converger les formats sans effacer le contexte de la source.",
      inputTitle: "Payload hétérogène",
      input:
        "Champs propres à Wazuh, Suricata ou syslog, avec des formats et sévérités natifs différents.",
      processTitle: "Construire une forme commune",
      process: [
        "Mapper Wazuh / Suricata vers la forme canonique inspirée ECS.",
        "Préserver temps, IP, description, source et contexte tenant.",
        "Construire le payload attendu par ingest_alert ; syslog a son propre consommateur.",
      ],
      outputTitle: "Événement canonique",
      output:
        "Champs comparables et payload d’ingestion, avec référence à l’origine lorsque conservée.",
      benefit:
        "Faciliter les traitements communs sans imposer le même format de log à tous les produits.",
      guard:
        "ECS-like ne signifie pas compatibilité ECS certifiée. Les guards et filtres tenant doivent être vérifiés pour chaque connecteur ; le schéma ne prouve pas une isolation absolue.",
      code: [
        "backend/app/application/normalization.py",
        "backend/app/interface/middleware/tenant.py",
      ],
    },
    {
      title: "Contextualiser la gravité",
      executor: "Pipeline + TI si activée",
      summary:
        "Préserver le sens de la sévérité et ajouter du contexte IoC lorsqu’il est disponible.",
      inputTitle: "Sévérité native + IP",
      input:
        "Exemple du mapping par défaut : la sévérité brute Suricata 1 est la plus grave, normalisée à 15.",
      processTitle: "Normaliser puis enrichir",
      process: [
        "Appliquer le mapping de sévérité sur l’échelle 0–15.",
        "Si TI activée et IP présente, rechercher un verdict avec cache / fournisseur.",
        "Enrichir la description pour malicious ou suspicious ; continuer en cas d’exception TI.",
      ],
      outputTitle: "Sévérité + contexte",
      output:
        "normalized_severity et enrichissement éventuel. Le contexte TI intervient avant la déduplication.",
      benefit:
        "Prioriser les signaux sans inverser l’échelle Suricata et apporter des indices lorsque le fournisseur en fournit.",
      guard:
        "unknown n’est pas clean. Certains seuils de rapports / jobs backend restent à harmoniser. Ni le score TI ni une synthèse IA ne remplacent une preuve vérifiée.",
      code: [
        "backend/app/application/pipeline.py",
        "frontend/src/lib/formatters.js",
      ],
    },
    {
      title: "Filtrer les répétitions",
      executor: "Mémoire du processus",
      summary:
        "Décider si le signal continue vers les règles dans la fenêtre courante.",
      inputTitle: "Signal contextualisé",
      input:
        "IP source, IP destination et signature utilisées pour calculer une empreinte.",
      processTitle: "Comparer dans une fenêtre",
      process: [
        "Calculer la clé puis consulter le DedupTracker.",
        "Mettre à jour les compteurs ; persister un PipelineEvent de doublon si configuré.",
        "Pour accepted, créer ou marquer l’alerte, alimenter le buffer et poursuivre.",
      ],
      outputTitle: "accepted / deduped / suppressed",
      output:
        "Les doublons et événements supprimés ne poursuivent pas ce chemin d’évaluation des règles.",
      benefit:
        "Éviter que chaque répétition du même signal entraîne à nouveau toutes les suites métier.",
      guard:
        "Le tracker n’est ni distribué ni durable. L’empreinte n’inclut pas le tenant. Une ligne déjà créée en amont n’est pas supprimée ; la TI est déjà passée avant ce filtre.",
      code: [
        "backend/app/application/pipeline.py",
        "backend/app/domain/pipeline_models.py",
      ],
    },
    {
      title: "Corréler et choisir les suites",
      executor: "Règles + bus local",
      summary:
        "Produire une détection expliquée, puis ouvrir les branches configurées plutôt qu’un automatisme unique.",
      inputTitle: "Alerte acceptée",
      input:
        "Événement normalisé et règles actives visibles pour le tenant, globales ou propres à son périmètre.",
      processTitle: "Évaluer et publier si match",
      process: [
        "Évaluer conditions, séquences ou comptages ; enrichir MITRE si la règle le prévoit.",
        "S’il existe un match, créer un RuleMatchEvent et tenter l’écriture de l’outbox SQL.",
        "Dispatcher localement : investigation et SOAR sont deux branches conditionnelles indépendantes.",
      ],
      outputTitle: "Match ou aucun match",
      output:
        "Sans match : alerte conservée, sans ce RuleMatchEvent. Avec match : notifications et handlers selon leurs propres gardes.",
      benefit:
        "Associer un motif explicable au signal et sélectionner des suites en fonction des règles et de la politique.",
      guard:
        "Aucun match ne prouve pas l’absence de menace. Une erreur d’outbox n’interdit pas à elle seule le dispatch ; l’investigation, qui relit l’outbox, peut alors manquer de contexte. Pas d’exactly once garanti.",
      code: [
        "backend/app/application/rules/engine.py",
        "backend/app/application/events.py",
      ],
    },
    {
      title: "Investiguer et documenter",
      executor: "Celery · file investigation",
      summary:
        "Rapprocher des preuves et produire un dossier partageable quand les gardes le permettent.",
      inputTitle: "Événement de l’outbox",
      input:
        "event_id et contexte tenant, après activation et garde de sévérité / tag investigate.",
      processTitle: "Collecter, scorer, synthétiser",
      process: [
        "Relire l’outbox et contrôler déduplication, quota et concurrence.",
        "Pour une nouvelle investigation admissible : créer la case et collecter les preuves TI, hôte, actifs, alertes liées et MITRE.",
        "Enregistrer score, synthèse et recommandations ; conserver les éléments manquants.",
      ],
      outputTitle: "Investigation / Case",
      output:
        "awaiting_response si des recommandations sont pending ; complete sinon. D’autres issues incluent linked, quota_exceeded, queued ou une erreur.",
      benefit:
        "Partager preuves, score décomposable, timeline et recommandations au lieu de laisser le contexte éparpillé.",
      guard:
        "Un worker doit consommer investigation. Le retour queued de la garde de concurrence ne prouve pas un nouveau job planifié. Le template LLM de repli peut marquer une complétion partielle ; awaiting_response ne signifie pas résolu.",
      code: [
        "backend/app/application/investigations/orchestrator.py",
        "backend/app/infrastructure/jobs/investigation_tasks.py",
      ],
    },
    {
      title: "Décider et répondre",
      executor: "Threads SOAR / jobs de réponse",
      summary:
        "Distinguer un playbook direct d’une réponse à une recommandation, puis vérifier l’issue réelle.",
      inputTitle: "Playbook ou recommandation",
      input:
        "PlaybookRun issu d’un match, ou recommandation d’investigation et ResponseRun selon la politique.",
      processTitle: "Autoriser puis exécuter si prévu",
      process: [
        "Vérifier activation, action implémentée, droits, connecteur et cible.",
        "Attendre l’approbation si requise. Le SOAR direct utilise un thread daemon ; la réponse a ses jobs Celery.",
        "Tracer les résultats et erreurs. Préparer un plan inverse uniquement lorsqu’un inverse existe.",
      ],
      outputTitle: "Attente / succès / échec",
      output:
        "Runs et résultats distincts. Le SOAR direct peut partir sans attendre une investigation.",
      benefit:
        "Séparer clairement la décision, l’approbation éventuelle et le résultat observé plutôt que confondre tous les états avec un succès.",
      guard:
        "push-config réseau est un dry-run (success: false). Un succès de dispatch / log notify ne prouve pas l’effet externe. Une annulation n’interrompt pas forcément une action déjà envoyée ; rollback non universel.",
      code: [
        "backend/app/application/soar/executor.py",
        "backend/app/application/response/executor.py",
      ],
    },
    {
      title: "Clôturer et capitaliser",
      executor: "Analyste + reporting",
      summary:
        "Conserver le raisonnement, rendre le résultat communicable et distinguer clôture, génération et livraison.",
      inputTitle: "Dossier et résultats connus",
      input:
        "Case, alertes liées, preuves, recommandations, notes et résultats d’exécution.",
      processTitle: "Documenter puis restituer",
      process: [
        "Conserver le triage sur CaseAlertLink et les notes dans la timeline.",
        "Clôturer explicitement ; le hook tente un rapport après le commit de clôture.",
        "Consulter, exporter ou livrer les formats disponibles selon le type et les canaux configurés.",
      ],
      outputTitle: "Timeline / rapport / export",
      output:
        "Un historique et des résultats consultables. CSV/PDF d’alertes, Markdown de case et rapports générés sont des chemins distincts.",
      benefit:
        "Réutiliser le contexte d’une enquête et transmettre une restitution compréhensible à d’autres acteurs.",
      guard:
        "Une génération échouée ne rouvre pas la case déjà clôturée. Le destinataire peut actuellement être marqué sent même si le sender retourne False sans exception : vérifier le transport. Une trace n’est ni une preuve de lecture ni un registre inviolable.",
      code: [
        "backend/app/application/cases.py",
        "backend/app/application/reporting/delivery.py",
      ],
    },
  ];

  const byId = (id) => document.getElementById(id);
  const setText = (id, value) => {
    byId(id).textContent = value;
  };
  const navLinks = [...document.querySelectorAll("[data-view]")];
  const stepButtons = [...document.querySelectorAll("[data-step]")];
  const componentButtons = [...document.querySelectorAll("[data-component]")];
  const dialog = byId("diagram-dialog");
  let selectedStep = 0;
  let selectedComponent = "pipeline";
  let zoom = 100;
  let diagramOpener = null;

  function renderCodeLinks(id, paths) {
    const links = paths.map((path) => {
      const link = document.createElement("a");
      link.href = codeRoot + path;
      link.textContent = path.split("/").slice(-2).join("/") + " ↗";
      link.title = path;
      link.className = "code-link";
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.setAttribute(
        "aria-label",
        `Ouvrir ${path} sur GitHub (nouvel onglet)`,
      );
      return link;
    });
    byId(id).replaceChildren(...links);
  }

  function replaceHash(hash) {
    // Hash-only navigation also works when index.html is opened directly from disk.
    try {
      window.history.replaceState(null, "", hash);
    } catch {
      window.location.hash = hash;
    }
  }

  function selectComponent(id, { announce = false, updateHash = false } = {}) {
    if (!Object.hasOwn(components, id)) return;
    selectedComponent = id;
    const component = components[id];
    for (const key of [
      "title",
      "kind",
      "description",
      "input",
      "output",
      "caution",
    ]) {
      setText(`component-${key}`, component[key]);
    }
    componentButtons.forEach((button) => {
      button.setAttribute(
        "aria-pressed",
        String(button.dataset.component === id),
      );
    });
    renderCodeLinks("component-links", component.code);
    if (updateHash) replaceHash(`#architecture/${id}`);
    if (announce) {
      setText(
        "component-status",
        `${component.title} sélectionné. Son rôle et ses limites sont affichés.`,
      );
      const inspector = document.querySelector(".component-panel");
      if (inspector.getBoundingClientRect().top > window.innerHeight - 100) {
        inspector.scrollIntoView({ block: "nearest" });
      }
    }
  }

  function selectStep(index, { announce = false, updateHash = false } = {}) {
    if (!Number.isInteger(index) || index < 0 || index >= steps.length) return;
    selectedStep = index;
    const step = steps[index];
    const number = String(index + 1).padStart(2, "0");
    setText("step-position", `ÉTAPE ${number} / 08`);
    for (const key of [
      "title",
      "summary",
      "executor",
      "input",
      "output",
      "benefit",
      "guard",
    ]) {
      setText(`step-${key}`, step[key]);
    }
    setText("step-input-title", step.inputTitle);
    setText("step-process-title", step.processTitle);
    setText("step-output-title", step.outputTitle);
    byId("step-process").replaceChildren(
      ...step.process.map((text) => {
        const item = document.createElement("li");
        item.textContent = text;
        return item;
      }),
    );
    stepButtons.forEach((button, buttonIndex) => {
      const active = buttonIndex === index;
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
    });
    byId("step-panel").setAttribute("aria-labelledby", `step-${number}`);
    byId("previous-step").disabled = index === 0;
    byId("next-step").disabled = index === steps.length - 1;
    renderCodeLinks("step-links", step.code);
    if (updateHash) replaceHash(`#parcours/${number}`);
    if (announce)
      setText("step-status", `Étape ${number} sur 8 : ${step.title}.`);
  }

  function applyRoute({ focus = false } = {}) {
    const [requestedView, detail] = window.location.hash.slice(1).split("/");
    const view = Object.hasOwn(pages, requestedView) ? requestedView : "apercu";
    if (dialog.open) dialog.close();
    document.querySelectorAll(".view").forEach((section) => {
      section.hidden = section.id !== view;
    });
    navLinks.forEach((link) => {
      if (link.dataset.view === view) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    setText("current-view", pages[view].label);
    setText("page-title", pages[view].title);
    setText("page-description", pages[view].description);
    document.title = `${pages[view].label} — Sentinel Bridge`;
    if (view === "parcours") {
      selectStep(
        /^0[1-8]$/.test(detail || "") ? Number(detail) - 1 : selectedStep,
      );
    }
    if (view === "architecture") {
      selectComponent(
        Object.hasOwn(components, detail) ? detail : selectedComponent,
      );
    }
    if (focus) {
      byId("contenu").focus({ preventScroll: true });
      window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    }
  }

  document.querySelector(".skip-link").addEventListener("click", (event) => {
    event.preventDefault();
    byId("contenu").focus();
  });

  componentButtons.forEach((button) => {
    button.addEventListener("click", () =>
      selectComponent(button.dataset.component, {
        announce: true,
        updateHash: true,
      }),
    );
  });
  stepButtons.forEach((button) => {
    button.addEventListener("click", () =>
      selectStep(Number(button.dataset.step), {
        announce: true,
        updateHash: true,
      }),
    );
  });
  document.querySelector(".step-grid").addEventListener("keydown", (event) => {
    const columns = getComputedStyle(
      event.currentTarget,
    ).gridTemplateColumns.split(" ").length;
    const offsets = {
      ArrowRight: 1,
      ArrowLeft: -1,
      ArrowDown: columns,
      ArrowUp: -columns,
    };
    let next;
    if (Object.hasOwn(offsets, event.key))
      next = (selectedStep + offsets[event.key] + steps.length) % steps.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = steps.length - 1;
    else return;
    event.preventDefault();
    selectStep(next, { announce: true, updateHash: true });
    stepButtons[next].focus();
  });
  for (const [id, offset] of [
    ["previous-step", -1],
    ["next-step", 1],
  ]) {
    byId(id).addEventListener("click", () => {
      selectStep(selectedStep + offset, { announce: true, updateHash: true });
      byId("step-panel").focus({ preventScroll: true });
      byId("step-panel").scrollIntoView({ block: "start" });
    });
  }

  function setZoom(value) {
    zoom = Math.max(50, Math.min(250, value));
    byId("diagram-image").style.width = `${zoom}%`;
    byId("zoom-level").value = `${zoom} %`;
    byId("zoom-out").disabled = zoom === 50;
    byId("zoom-in").disabled = zoom === 250;
  }
  document.querySelectorAll("a[data-diagram]").forEach((link) => {
    link.addEventListener("click", (event) => {
      if (
        event.button !== 0 ||
        event.metaKey ||
        event.ctrlKey ||
        event.shiftKey ||
        event.altKey ||
        typeof dialog.showModal !== "function"
      )
        return;
      event.preventDefault();
      diagramOpener = link;
      setText("diagram-title", link.dataset.diagram);
      const image = byId("diagram-image");
      image.src = link.getAttribute("href");
      image.alt = link.dataset.diagram;
      setZoom(100);
      dialog.showModal();
      byId("diagram-scroll").scrollTo(0, 0);
      byId("close-diagram").focus();
    });
  });
  byId("zoom-in").addEventListener("click", () => setZoom(zoom + 25));
  byId("zoom-out").addEventListener("click", () => setZoom(zoom - 25));
  byId("zoom-reset").addEventListener("click", () => {
    setZoom(100);
    byId("diagram-scroll").scrollTo(0, 0);
  });
  byId("close-diagram").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () =>
    diagramOpener?.focus({ preventScroll: true }),
  );
  dialog.addEventListener("click", (event) => {
    const bounds = dialog.getBoundingClientRect();
    if (
      event.target === dialog &&
      (event.clientX < bounds.left ||
        event.clientX > bounds.right ||
        event.clientY < bounds.top ||
        event.clientY > bounds.bottom)
    )
      dialog.close();
  });
  dialog.addEventListener("keydown", (event) => {
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.key === "+" || event.key === "=") {
      event.preventDefault();
      setZoom(zoom + 25);
    }
    if (event.key === "-") {
      event.preventDefault();
      setZoom(zoom - 25);
    }
    if (event.key === "0") {
      event.preventDefault();
      byId("zoom-reset").click();
    }
  });

  document.documentElement.classList.add("is-interactive");
  document.querySelectorAll("[data-enhanced]").forEach((element) => {
    element.hidden = false;
  });
  window.addEventListener("hashchange", () => {
    // A skip link moves focus within the active view; it must not reset the route.
    if (window.location.hash !== "#contenu") applyRoute({ focus: true });
  });
  // Refreshing a deep link must yield the same selected component or step.
  applyRoute();
  selectComponent(selectedComponent);
  selectStep(selectedStep);
})();
