import pefile
import peutils
import re

standardSections = [".text", ".bss", ".data",".rdata",".idata",".edata",".pdata",".rsrc",".reloc"]
standardReg = "^"+ "$|^".join(standardSections) + "$"

def getPeSectionsFeature(exe):
    res = {"amountOfSections" : len(exe.sections)}
    amountOfSuspiciousSections = 0
    for section in exe.sections:
        decodedName = section.Name.decode("ascii").rstrip('\x00')
        if (re.search(standardReg,decodedName) == None):
            amountOfSuspiciousSections += 1
        #if any(se)
    res['amountOfSuspiciousSections'] = amountOfSuspiciousSections
    print(amountOfSuspiciousSections)
        
def getPeFeatures(exe):
    res = {
        "seemsPacked" : peutils.is_probably_packed(exe)
    }
    print(res)

exe_file_path = '17.exe'
exe = pefile.PE(exe_file_path)
getPeSectionsFeature(exe)
getPeFeatures(exe)

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