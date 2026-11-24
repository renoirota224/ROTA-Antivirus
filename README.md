# ROTA Antivirus

Logiciel Windows de RotaGaming pour contrôler un disque avant sa livraison.

- Analyse un disque sans lancer ses programmes.
- Répare les programmes touchés par Expiro quand la réparation est prouvée.
- Remplace un fichier seulement par une copie officielle signée.
- Isole ce qui ne peut pas être réparé dans `_QUARANTAINE_ROTA`, sans rien supprimer.
- Range `RECYCLER.BIN` et bloque le retour de PlugX.
- Sort la quarantaine du disque vers le PC après vérification, et peut la remettre.
- Filtre les fichiers, montre leur emplacement et garde l'historique des contrôles.
- Donne un verdict de livraison et un rapport.

## Tester sur une clé USB

Branche une clé **vide**, lance `tests\Preparer-Cle-Test.bat`, puis contrôle la clé dans ROTA Antivirus. Les fichiers créés sont de simples textes inoffensifs. `tests\Nettoyer-Cle-Test.bat` les retire ensuite.

## Limites

ROTA Antivirus reconnaît seulement Expiro, Grenam, PlugX et la forme UPX1 étudiés par RotaGaming. Il ne remplace pas un antivirus complet. Un verdict « Prêt » ne prouve pas qu'un disque est sans aucun virus.

Le dossier `_QUARANTAINE_ROTA` contient des fichiers infectés inactifs. Il ne doit jamais être copié chez un client.

## Fabrication

GitHub Actions teste le moteur, compile l'application et fabrique le `Setup.exe` avec Inno Setup. Pour publier une version :

```powershell
git tag v1.0.0
git push origin v1.0.0
```

Le fichier d'installation apparaît ensuite dans les Releases du dépôt, avec son empreinte SHA-256.
