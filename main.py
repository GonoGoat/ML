import pefile
import peutils
import re

standardSections = [".text", ".bss", ".data",".rdata",".idata",".edata",".pdata",".rsrc",".reloc"]
standardReg = "^"+ "$|^".join(standardSections) + "$"

#https://stackoverflow.com/questions/53890543/enumerating-all-modules-for-a-binary-using-python-pefile-win32api
def analyzeImportedDLL(exe):
    for entry in exe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll)

def getEntropyFeatures(entropies):
    entropies = list(filter(lambda en: en != 0,entropies))
    return {
        "amountOfZeroEntropy" : entropies.count(0),
        "lowestEntropy" : min(entropies),
        "highestEntropy" : max(entropies)
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
    return { "seemsPacked" : peutils.is_probably_packed(exe)}

def getFeatures(exe):
    res = {}
    res |= seemsPacked(exe)
    res |= getPeSectionsFeature(exe)
    print(res)

exe_file_path = '0.exe'
exe = pefile.PE(exe_file_path)
getFeatures(exe)
findDLL(exe)
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