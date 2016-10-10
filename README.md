# netArchae 
Version 3.1.3 of Autopsy Required
Autopsy Module that extracts Packet Captures (pcaps) from Data Sources.
It sorts them under a "PCAPs" tab within "Interesting Files" and allows the extracted pcaps to be parsed by KeywordSearch.

In order to use this module, the user must have Autopsy version 3.1.3 installed. Directions to load
and run the module are outlined below:
1. Run Autopsy
2. Add Data Source
3. Navigate to Tools on the Autopsy Menu
a. Choose Python Plugins
b. Create a folder with the name of the plugin
c. Copy netarchae.py into the folder
d. Close out of the Python Plugins folder
4. Right click on the Data Source you would like to parse for packet captures
5. Select Run Ingest Modules
6. Check the box next to the modules you would like to run
  a. in this case, choose NetArchae (note that you can choose multiple modules)
7. Once the module has run, provided it yields results, you will see a new "PCAPs" tab under "Interesting Items". You can also see extracted pcaps by generating a report or clicking on the "Ingest Messages" icon.

