from pefile import PE
from peutils import is_probably_packed
import re

standardSections = [".text", ".bss", ".data",".rdata",".idata",".edata",".pdata",".rsrc",".reloc"]
standardReg = "^"+ "$|^".join(standardSections) + "$"

def getOptionalHeaderFeatures(exe):
    return {
        
    }

def getFileHeaderFeatures(exe):
    #for entry in exe.FILE_HEADER.__keys__:
       # res[entry] = exe.FILE_HEADER.__dict__[entry]
    return {
        "Machine" : exe.FILE_HEADER.Machine,
        "NumberOfSections" : exe.FILE_HEADER.NumberOfSections,
        "TimeDateStamp" : exe.FILE_HEADER.TimeDateStamp,
        "PointerToSymbolTable" : exe.FILE_HEADER.PointerToSymbolTable,
        "NumberOfSymbols" : exe.FILE_HEADER.NumberOfSymbols,
        "SizeOfOptionalHeader" : exe.FILE_HEADER.SizeOfOptionalHeader,
        "Characteristics" : exe.FILE_HEADER.Characteristics
    }

#https://stackoverflow.com/questions/53890543/enumerating-all-modules-for-a-binary-using-python-pefile-win32api
def getImportedDLLFeatures(exe):
    for entry in exe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll.decode("ascii"))

def getEntropyFeatures(entropies):
    filteredEntropies = list(filter(lambda en: en != 0,entropies))
    return {
        "amountOfZeroEntropy" : entropies.count(0),
        "lowestEntropy" : min(filteredEntropies),
        "highestEntropy" : max(filteredEntropies)
    }
    
def isSuspiciousSectionName(section):
    decodedName = section.Name.decode("ascii").rstrip('\x00')
    return re.search(standardReg,decodedName) == None

def getPeSectionsFeature(exe):
    res = {
        "amountOfSections" : len(exe.sections),
        "amountOfSuspiciousSections" : 0,
        "amountOfZeroEntropy" : 0
    }
    entropies = []
    for section in exe.sections:
        entropies.append(section.get_entropy())
        if isSuspiciousSectionName(section): res["amountOfSections"] += 1
    res |= getEntropyFeatures(entropies)
    return res
    
        
def seemsPacked(exe):
    return { "seemsPacked" : is_probably_packed(exe)}

def getFeatures(exe):
    res = {}
    res |= seemsPacked(exe)
    res |= getPeSectionsFeature(exe)
    res |= getFileHeaderFeatures(exe)
    print(res)

exe_file_path = '7026.exe'
exe = PE(exe_file_path)
getFeatures(exe)
getImportedDLLFeatures(exe)
getOptionalHeaderFeatures(exe)
#getPeFeatures(exe)

# amountOfSections = getAmountOfSection(exe)

'''try:
  #parse exe file
  exe = pefile.PE(exe_file_path)
  sections = exe.parse_sections()
  print(sections)
  for section in sections.sections:
      print(section)
  try:
    #call the function we created earlier
    # fine_disassemble(exe)
    print("done")
  except:
    print('something is wrong with this exe file')
except:
  print('pefile cannot parse this file')
  '''
# objdump -d --no-addresses --no-show-raw-insn <file>

# Analyse fichier PE
# Extraction/Conversion de toutes les lignes de de caractères dans dissassembler
# Liste des entrées registres modifiées après exécution
# Analyse traffic réseau ?
# Mesure entropie ?
# Comaparaison signature