# CloudLens

CloudLens è uno strumento di **Azure environment assessment** sviluppato in .NET 8 con interfaccia WPF.

L'obiettivo è analizzare un ambiente Azure in modalità **read-only**, raccogliere informazioni sulle risorse e produrre una valutazione strutturata relativa a:

* Security
* Cost
* Reliability
* Performance
* Operations
* Architecture
* Governance

Il progetto è strutturato in un **Core indipendente dalla UI**, con collector Azure, motore di assessment, layer di intelligence, quality assessment e sistemi di esportazione.

---

## Stato del progetto

**Phase 13 — Assessment Quality Layer**

Le funzionalità principali attualmente implementate includono:

* Azure tenant/subscription discovery
* Azure Resource Graph inventory
* Resource enrichment tramite Azure Resource Manager
* Resource relationships
* Azure Advisor integration
* Deterministic assessment engine
* Resource coverage analysis
* Category scoring
* Findings e severity classification
* Assessment Intelligence
* Risk prioritization
* Quick Wins
* Systemic Risks
* Impact analysis
* Remediation roadmap
* Assessment Quality & Coverage
* JSON export
* Excel export
* Professional HTML report
* WPF graphical interface
* Automated Core tests

---

## Architettura

```text
CloudLens
│
├── CloudLens.Core
│   ├── Azure
│   │   ├── AzureCollector
│   │   ├── Resource Graph
│   │   ├── Resource Manager enrichment
│   │   ├── Advisor
│   │   └── Diagnostics
│   │
│   ├── Analysis
│   │   ├── Assessment Engine
│   │   ├── Coverage Analysis
│   │   └── Assessment Intelligence
│   │
│   ├── Models
│   ├── Export
│   │   ├── JSON
│   │   ├── Excel
│   │   └── HTML
│   └── Quality
│
├── CloudLensGUI
│   └── WPF interface
│
├── CloudLens.Core.Tests
│   └── Automated tests
│
└── src
    └── CloudLens.ps1
```

---

## Assessment Quality

CloudLens distingue tra qualità dell'assessment e semplice presenza delle risorse.

Ogni subscription può essere classificata come:

* **Complete** — assessment completato correttamente
* **Partial** — assessment completato con limitazioni
* **Failed** — assessment non completato correttamente
* **Unsupported** — assessment non supportato

La Quality layer espone inoltre:

* subscription coverage
* resource enrichment coverage
* metric coverage
* supported resource types
* generic resource types
* unsupported resource types
* errori e limitazioni
* qualità per singola subscription

Le limitazioni vengono mantenute nell'output invece di essere semplicemente scartate.

---

## Assessment Intelligence

Il layer di intelligence consolida i risultati dell'assessment e permette di identificare:

* rischi prioritari
* quick wins
* systemic risks
* potenziale impatto economico
* remediation roadmap

L'intelligence è deterministica e basata sui risultati prodotti dal Core.

Non sono attualmente presenti remediation automatiche o decisioni autonome.

---

## Export

CloudLens supporta tre formati di report:

### JSON

Output strutturato contenente:

* assessment results
* findings
* scoring
* intelligence
* quality information
* coverage
* subscription details

### Excel

Workbook strutturato con fogli dedicati, tra cui:

* Summary
* Quality
* Subscriptions
* Resources
* Findings
* Intelligence
* Remediation
* Metrics
* Coverage

### HTML

Report professionale con:

* Executive Summary
* Assessment Intelligence
* Assessment Quality
* Category Scores
* Assessment Coverage
* Subscriptions
* Resource Inventory
* Findings
* Remediation Plan
* Metrics
* Assessment Methodology

---

## Interfaccia

La GUI è sviluppata in **WPF** e permette di:

* eseguire l'assessment
* visualizzare i risultati
* consultare Assessment Intelligence
* visualizzare rischi e remediation roadmap
* esportare HTML, JSON ed Excel

La GUI utilizza il Core come motore dell'assessment, mantenendo separata la logica applicativa dalla presentazione.

---

## Azure access

L'accesso ad Azure utilizza le librerie ufficiali Microsoft/Azure SDK e autenticazione tramite `Azure.Identity`.

L'assessment è progettato per operare in modalità **read-only**.

Non vengono effettuate modifiche automatiche alle risorse Azure.

---

## Testing

Il progetto dispone di un progetto dedicato:

```text
CloudLens.Core.Tests
```

I test coprono principalmente:

* Assessment Intelligence
* Assessment Quality
* JSON export
* HTML report
* assessment aggregation

Stato attuale della suite:

```text
21 tests
21 passed
0 failed
```

---

## Requisiti

* Windows
* .NET 8 SDK
* Accesso ad Azure per gli assessment reali
* Permessi Azure sufficienti per le operazioni di lettura richieste

---

## Avvio

Dalla root del repository:

```powershell
dotnet build .\CloudLens.Core\CloudLens.Core.csproj
dotnet build .\CloudLensGUI\CloudLensGUI.csproj
```

Per avviare la GUI:

```powershell
cd CloudLensGUI
dotnet run
```

Per eseguire i test:

```powershell
dotnet test .\CloudLens.Core.Tests\CloudLens.Core.Tests.csproj
```

---

## Repository

Il progetto è disponibile su GitHub:

[CloudLens — GitHub repository](https://github.com/leucifrancesco/CloudLens.git?utm_source=chatgpt.com)

---

## Roadmap

Le prossime evoluzioni verranno definite sulla base della maturità dell'attuale assessment engine e della copertura delle risorse Azure.

Le priorità saranno orientate principalmente a:

1. aumentare la copertura delle risorse Azure;
2. migliorare la profondità degli analyzer;
3. aumentare la qualità e completezza dell'assessment;
4. migliorare scoring e remediation;
5. evolvere ulteriormente reporting e productizzazione.

Le funzionalità future verranno introdotte incrementando progressivamente la copertura senza compromettere la stabilità del Core esistente.
