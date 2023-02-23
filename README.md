# RaspiNAS-App

*-- German Version --*

Die RaspiNAS-App ist das Gegenstück zum Socket-Interface des [Python-RaspiNAS](https://github.com/nitrescov/Python-RaspiNAS) Servers. Sie ermöglicht es, große Datenmengen über eine reine Socket-Verbindung (TCP) besonders schnell und effizient zu übertragen.

Die App ist sowohl unter **Windows** als auch unter **Linux** lauffähig. Die entsprechenden ausführbaren Dateien befinden sich in einem Archiv unter dem jeweiligen Release.

## Einrichtung

1. Passendes Archiv von der Release-Seite herunterladen und entpacken.
2. Sprache, Server-IP und Port in der `config.json` Datei eintragen. **Achtung:** Die `config.json` muss sich unbedingt weiterhin im gleichen Verzeichnis wie das `RaspiNAS-App` Script befinden.
3. Die EXE-Datei oder das Linux-Script ausführen, ggf. vorher mit `chmod +x RaspiNAS-App` ausführbar machen.

## Ausführbare Datei selbst erzeugen

Dies kann bspw. hilfreich sein, um herauszufinden, ob das Programm auch unter macOS lauffähig ist.

Die RaspiNAS-App wurde mittels [PyInstaller](https://pyinstaller.org) gepackt. Folgende Abhängigkeiten müssen hierfür erfüllt sein:

* PyInstaller - `pip install -U pyinstaller`
* Tkinter - `apt install python3-tk` / `pacman -S tk`
* Pillow (für die GIF -> ICO Konvertierung unter Windows) - `pip install -U Pillow`

Dann kann die App im Hauptverzeichnis mit folgendem Befehl gepackt werden: `pyinstaller --onefile --windowed --icon=icons/raspinas.gif RaspiNAS-App.py`

> Hinweis:<br>
> Die Socket-Verbindung überträgt Daten zwar besonders schnell, ist dabei aber nicht verschlüsselt. Aus diesem Grund sollte sie ausschließlich im lokalen, nicht öffentlichen Netzwerk verwendet werden (z.B. für Backups).

---

*-- English Version --*

The RaspiNAS-App is the counterpart to the socket interface of the [Python-RaspiNAS](https://github.com/nitrescov/Python-RaspiNAS) server. It makes it possible to transfer large amounts of data over a pure socket connection (TCP) particularly quickly and efficiently.

The app runs under **Windows** as well as under **Linux**. The corresponding executable files are located in an archive under the respective release.

## Setup

1. Download the appropriate archive from the release page and unpack it.
2. Enter language, server IP and port in the `config.json` file. **Attention:** The `config.json` must be in the same directory as the `RaspiNAS-App` script.
3. Execute the EXE file or the Linux script, if necessary make it executable with `chmod +x RaspiNAS-App` first.

## Build the executable file from source

This can be helpful, for example, to find out whether the program is also executable under macOS.

The RaspiNAS-App was packaged using [PyInstaller](https://pyinstaller.org). The following dependencies must be fulfilled therefor:

* PyInstaller - `pip install -U pyinstaller`
* Tkinter - `apt install python3-tk` / `pacman -S tk`
* Pillow (for the GIF -> ICO conversion under Windows) - `pip install -U Pillow`

Then the app can be packaged in the main directory with the following command: `pyinstaller --onefile --windowed --icon=icons/raspinas.gif RaspiNAS-App.py`

> Note:<br>
> Although the socket connection transfers data particularly quickly, it is not encrypted. For this reason, it should only be used in the local, non-public network (e.g. for backups).
