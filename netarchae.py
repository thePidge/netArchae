'''
NetArchae v1.0
Version 3.1.3 of Autopsy Required
This module extracts Packet Captures (pcaps) from Data Sources. 
It sorts them under "Interesting Files" and allows the extracted pcaps to be parsed by KeywordSearch. 
'''

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager

# Defines the name and details of the module and allows Autopsy to create instances of the modules that will do the anlaysis.
class NetArchaeologist(IngestModuleFactoryAdapter):

    moduleName = "NetArchae"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Extracts PCAP files"

    def getModuleVersionNumber(self):
        return "1.0"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return netArchae()

class netArchae(FileIngestModule):

    _logger = Logger.getLogger(NetArchaeologist.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0
        pass

    def process(self, file):
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or 
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or 
            (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        # Flags files with .pcap extensions and makes a blackboard artifact.
        if file.getName().lower().endswith(".pcap"):

            self.log(Level.INFO, "Found a pcap file: " + file.getName())
            self.filesFound+=1

            # Makes an artifact on the blackboard.
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, 
                              NetArchaeologist.moduleName, "Text Files")            
            art.addAttribute(att)

            try:
            # Indexes the artifact for keyword search.
                blackboard.indexArtifact(art)
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            # Notifies user that there is a new artifact.
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(NetArchaeologist.moduleName, 
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

            artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            for artifact in artifactList:
                attributeList = artifact.getAttributes();
                for attrib in attributeList:
                    self.log(Level.INFO, attrib.toString())

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        #  Sends a message to the ingest inbox with the number of PCAP files found.
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, NetArchaeologist.moduleName, 
                str(self.filesFound) + " PCAP files found")
        ingestServices = IngestServices.getInstance().postMessage(message)