from pefile import PE, PEFormatError
from peutils import is_probably_packed
import re

standardSections = [".text", ".bss", ".data",".rdata",".idata",".edata",".pdata",".rsrc",".reloc"]
standardReg = "^"+ "$|^".join(standardSections) + "$"

dlls = ["advapi32.dll","user32.dll","ws2_32.dll","wininet.dll","kernel32.dll","shell32.dll"]

features = [
    # File Header
    "NumberOfSections",
    "TimeDateStamp",
    "PointerToSymbolTable",
    "NumberOfSymbols",
    "SizeOfOptionalHeader",
    "Characteristics",
    # Entropy
    "amountOfZeroEntropy",
    "lowestEntropy",
    "highestEntropy",
    # Sections
    "amountOfSuspiciousSections",
    "amountOfZeroEntropy",
    # PE Format
    "isPE",
    # Packing
    "seemsPacked",
    # Relocation
    "relocationsOverlapEntrypoint",
    "sequentialRelocs",
    # DLL
    "amountOfImportedDLL",
    # Optional Header
    "SizeOfCode",
    "SizeOfInitializedData",
    "SizeOfUninitializedData",
    "AddressOfEntryPoint",
    "ImageBase",
    "MajorSubsystemVersion",
    "NumberOfRvaAndSizes",
    "SizeOfImage",
    "SectionAlignment",
    "FileAlignment"
] + dlls

# https://github.com/zpeterson/pefile/blob/sphinx-autodoc/peutils.py#L499
def hasSuspiciousRelocations(exe):
    res = {
        "relocationsOverlapEntrypoint" : 0,
        "sequentialRelocs" : 0
    }
    if hasattr(exe, 'DIRECTORY_ENTRY_BASERELOC'):
        for base_reloc in exe.DIRECTORY_ENTRY_BASERELOC:
            last_reloc_rva = None
            for reloc in base_reloc.entries:
                if reloc.rva <= exe.OPTIONAL_HEADER.AddressOfEntryPoint <= reloc.rva + 4:
                    res["relocationsOverlapEntrypoint"] = 1

                if last_reloc_rva is not None and last_reloc_rva <= reloc.rva <= last_reloc_rva + 4:
                    res["sequentialRelocs"] += 1

                last_reloc_rva = reloc.rva
    return res

def getOptionalHeaderFeatures(exe):
    return {
        "SizeOfCode" : exe.OPTIONAL_HEADER.SizeOfCode,
        "SizeOfInitializedData" : exe.OPTIONAL_HEADER.SizeOfInitializedData,
        "SizeOfUninitializedData" : exe.OPTIONAL_HEADER.SizeOfUninitializedData,
        "AddressOfEntryPoint" : exe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "ImageBase" : exe.OPTIONAL_HEADER.ImageBase,
        "MajorSubsystemVersion" : exe.OPTIONAL_HEADER.MajorSubsystemVersion,
        "NumberOfRvaAndSizes" : exe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
        "SizeOfImage" : exe.OPTIONAL_HEADER.SizeOfImage,
        "SectionAlignment" : exe.OPTIONAL_HEADER.SectionAlignment,
        "FileAlignment" : exe.OPTIONAL_HEADER.FileAlignment,
    }

def getFileHeaderFeatures(exe):
    #for entry in exe.FILE_HEADER.__keys__:
       # res[entry] = exe.FILE_HEADER.__dict__[entry]
    return {
        "NumberOfSections" : exe.FILE_HEADER.NumberOfSections,
        "TimeDateStamp" : exe.FILE_HEADER.TimeDateStamp,
        "PointerToSymbolTable" : exe.FILE_HEADER.PointerToSymbolTable,
        "NumberOfSymbols" : exe.FILE_HEADER.NumberOfSymbols,
        "SizeOfOptionalHeader" : exe.FILE_HEADER.SizeOfOptionalHeader,
        "Characteristics" : exe.FILE_HEADER.Characteristics
    }

#https://stackoverflow.com/questions/53890543/enumerating-all-modules-for-a-binary-using-python-pefile-win32api
def getImportedDLLFeatures(exe):
    res = {
        "amountOfImportedDLL" : 0
    }
    dll = []
    if hasattr(exe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in exe.DIRECTORY_ENTRY_IMPORT:
            try:   
                dll.append(entry.dll.decode("ascii").lower())
            except (UnicodeDecodeError):
                dll.append("<unreadable>")
            res["amountOfImportedDLL"] += 1
        for studiedDll in dlls:
            if studiedDll in dll:
                res[studiedDll] = 1
            else:
                res[studiedDll] = 0
    else:
        for studiedDll in dlls:
            res[studiedDll] = 0
    return res
    

def getEntropyFeatures(entropies):
    filteredEntropies = list(filter(lambda en: en != 0,entropies))
    return {
        "amountOfZeroEntropy" : entropies.count(0),
        "lowestEntropy" : min(filteredEntropies),
        "highestEntropy" : max(filteredEntropies)
    }
    
def isSuspiciousSectionName(section):
    try:
        decodedName = section.Name.decode("ascii").rstrip('\x00')
    except (UnicodeDecodeError):
        decodedName = "<unreadable>"  
    return re.search(standardReg,decodedName) == None

def getPeSectionsFeature(exe):
    res = {
        "amountOfSuspiciousSections" : 0,
        "amountOfZeroEntropy" : 0
    }
    entropies = []
    for section in exe.sections:
        entropies.append(section.get_entropy())
        if isSuspiciousSectionName(section): res["amountOfSuspiciousSections"] += 1
    res |= getEntropyFeatures(entropies)
    return res
    
        
def seemsPacked(exe):
    if is_probably_packed(exe):
        return { "seemsPacked" : 1 }
    else:
        return { "seemsPacked" : 0 }
        
def getFeatures(exe_file_path):
    res = {}
    try:
        exe = PE(exe_file_path)
        res |= {"isPE" : 1}
        res |= getImportedDLLFeatures(exe)
        res |= getOptionalHeaderFeatures(exe)
        res |= seemsPacked(exe)
        res |= getPeSectionsFeature(exe)
        res |= getFileHeaderFeatures(exe)
        res |= hasSuspiciousRelocations(exe)
    except(PEFormatError):
        for keys in features:
            res[keys] = 0
        res |= {"isPE" : 0}
    return res

#res = getFeatures("./heh-cybersecurity-2023-2024/trainset/trainset/safe/1550.exe")
res = getFeatures("0.exe")
print(res)

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