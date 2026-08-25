# CloudLens — versione locale WPF

Questa è una ricostruzione locale della UI/assessment demo emersa dall'app Emergent. Non è una conversione 1:1 del backend Python/React perché i sorgenti completi di Emergent non sono disponibili.

## Requisiti
- Windows
- .NET 8 SDK

## Avvio
```powershell
cd CloudLensGUI
dotnet run
```

## Collaudo
Premere **Carica demo**. Vengono mostrati 11 finding, scoring WAF e risparmi.

## Prossimo sviluppo
1. Spostare nel progetto Core le regole deterministiche reali di CloudLens.
2. Implementare Azure collector read-only con Azure.Identity/Azure.ResourceManager.
3. Export JSON + Excel per la v0.9.
4. Report PDF.
5. Layer AI per v1.0.
