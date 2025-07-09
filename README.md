# progetto-sicurezza
Repository di Tommaso Romagnoli per la prova pratica dell'esame Sicurezza dell'Informazione M

Il progetto consiste nell'implementazione del protocollo di identificazione mutua tramite sfida/risposta visto a lezione e alla simulazione di un attacco di reflection su di esso.
Si utilizzano funzioni crittograficamente sicure di python per generare nonce casuali e per calcolare impronte tramite hash.
Successivamente viene implementata una versione migliorata del protocollo vista a lezione, con un analogo attacco di reflection.
Per fare ciò sono stati realizzati i seguenti eseguibili python:

*[Primo protocollo](protocollo1.py): Viene implementato il protocollo che prevede la mutua identificazione tramite sfida/risposta con messaggi simmetrici. In questo eseguibile vengono simulate due entità (Alice e Bob) che condividono un segreto e che si vogliono identificare. Per fare ciò si usano le librerie di python hashlib e secrets che permettono rispettivamente di creare impronte tramite una funzione hash sicura (come SHA-256) e di creare nonce casuali tramite PRNG crittograficamente sicuri.
*[Attacco di reflection al primo protocollo](attacco_protocollo1.py): In questo esempio si simula un attacco di reflection, dove Charlie (l'attaccante) cerca di identificarsi come Alice verso Bob instaurando con quest'ultimo 2 sessioni. Questo attacco va a buon fine e mostra le vulnerabilità del primo protocollo, nello specifico la possibilità di poter riutilizzare messaggi ottenuti in sessioni diverse.
*[Secondo protocollo](protocollo2.py): Questo protocollo visto a lezione mira ad eliminare le vulnerabilità descritte sopra. Aggiunge asimmetria ai messaggi scambiati dalle parti; nello specifico richiede che nella risposta ad una sfida venga anche inviato l'identificativo della destinazione, rendendo impossibile un attacco di reflection per un attaccante.
*[Attacco di reflection al secondo protocollo](attacco_protocollo2.py): Questa simulazione è analoga a quella precedente, ma si riferisce al protocollo 2. Mostra come un attacco di reflection da parte di Charlie fallisca, grazie al fatto che il destinatario indicato nell'impronta è diverso da quello aspettato da Bob.

