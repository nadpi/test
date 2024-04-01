#!/usr/bin/python3
import pefile
import math

#malware file
malware_file = "/home/kali/malwares/50dfd5f2b25155518ea3468c2cd6442957812310b07185319fd2e7aeb7bebdb5.exe"

pe = pefile.PE(malware_file)

entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint


image_base = pe.OPTIONAL_HEADER.ImageBase

sectionsNb = pe.FILE_HEADER.NumberOfSections

optional_header_size = pe.FILE_HEADER.SizeOfOptionalHeader

machine = pe.FILE_HEADER.Machine

dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics

characteristics = pe.FILE_HEADER.Characteristics

major_linker_version = pe.OPTIONAL_HEADER.MajorLinkerVersion

minor_linker_version = pe.OPTIONAL_HEADER.MinorLinkerVersion

size_of_code = pe.OPTIONAL_HEADER.SizeOfCode

size_of_initialized_data = pe.OPTIONAL_HEADER.SizeOfInitializedData

base_of_code = pe.OPTIONAL_HEADER.BaseOfCode

try:
    base_of_data = pe.OPTIONAL_HEADER.BaseOfData
except AttributeError:
    base_of_data = 0

section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

file_alignment = pe.OPTIONAL_HEADER.FileAlignment

major_os_ver = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion

minor_os_ver = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion

major_img_ver = pe.OPTIONAL_HEADER.MajorImageVersion

minor_img_ver = pe.OPTIONAL_HEADER.MinorImageVersion

major_subsys_ver = pe.OPTIONAL_HEADER.MajorSubsystemVersion

minor_subsys_ver = pe.OPTIONAL_HEADER.MinorSubsystemVersion

size_of_img = pe.OPTIONAL_HEADER.SizeOfImage

size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders

checksum  = pe.OPTIONAL_HEADER.CheckSum

subsys = pe.OPTIONAL_HEADER.Subsystem

size_of_stack_reserve = pe.OPTIONAL_HEADER.SizeOfStackReserve

size_of_stack_commit = pe.OPTIONAL_HEADER.SizeOfStackCommit

size_of_heap_reserve = pe.OPTIONAL_HEADER.SizeOfHeapReserve

size_of_heap_commit = pe.OPTIONAL_HEADER.SizeOfHeapCommit

loader_flags = pe.OPTIONAL_HEADER.LoaderFlags

no_of_rva_sizes = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

def calculate_entropy(data):
    entropy = 0
    if len(data) > 0:
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log(p_x, 2)
    return entropy

def mean_section_entropy(pe):
    section_entropies = []
    for section in pe.sections:
        entropy = calculate_entropy(section.get_data())
        section_entropies.append(entropy)
    if section_entropies:
        mean_entropy = sum(section_entropies) / len(section_entropies)
        return mean_entropy
    else:
        return None

def min_section_entropy(pe):
    section_entropy = calculate_entropy(pe.sections[0].get_data())
    for section in pe.sections[1:]:
        entropy = calculate_entropy(section.get_data())
        if entropy < section_entropy:
            section_entropy = entropy
    return section_entropy

def max_section_entropy(pe):
    section_entropy = calculate_entropy(pe.sections[0].get_data())
    for section in pe.sections[1:]:
        entropy = calculate_entropy(section.get_data())
        if entropy > section_entropy:
            section_entropy = entropy
    return section_entropy

def get_section_raw_data_size(peSection):
    return peSection.SizeOfRawData

def sections_mean_rawsize(pe):
    sections_raw = []
    for section in pe.sections:
        rawsize = get_section_raw_data_size(section)
        sections_raw.append(rawsize)
    if sections_raw:
        meanRAW = sum(sections_raw) / len(sections_raw)
        return meanRAW
    else:
        return None

def sections_min_rawsize(pe):
    section_raw = get_section_raw_data_size(pe.sections[0])
    for section in pe.sections[1:]:
        rawsize = get_section_raw_data_size(section)
        if rawsize < section_raw:
            section_raw = rawsize
    return section_raw

def sections_max_rawsize(pe):
    section_raw = get_section_raw_data_size(pe.sections[0])
    for section in pe.sections[1:]:
        rawsize = get_section_raw_data_size(section)
        if rawsize > section_raw:
            section_raw = rawsize
    return section_raw

def get_virtual_size(peSection):
    return peSection.Misc_VirtualSize

def sections_mean_virtual_size(pe):
    section_virts = []
    for section in pe.sections:
        virtSize = get_virtual_size(section)
        section_virts.append(virtSize)
    if section_virts:
        meanVirt = sum(section_virts) / len(section_virts)
        return meanVirt
    else:
        return None

def sections_min_virtsize(pe):
    section_virt = get_virtual_size(pe.sections[0])
    for section in pe.sections[1:]:
        virtsize = get_virtual_size(section)
        if virtsize < section_virt:
            section_virt = virtsize
    return section_virt

def sections_max_virtsize(pe):
    section_virt = get_virtual_size(pe.sections[0])
    for section in pe.sections[1:]:
        virtsize = get_virtual_size(section)
        if virtsize > section_virt:
            section_virt = virtsize
    return section_virt

def imports_count(pe):
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        imported_dlls = set()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imported_dlls.add(entry.dll.decode())
        return len(imported_dlls)
    else:
        return 0

def total_imports_count(pe):
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        total_imports = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            total_imports += len(entry.imports)
        return total_imports
    else:
        return 0

def ordinal_imports_count(pe):
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        total_ordinal_imports = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.ordinal is not None:
                    total_ordinal_imports += 1
        return total_ordinal_imports
    else:
        return 0

def exports_count(pe):
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    else:
        return 0

def resources_count(pe):
    res = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            res += 1
        return res
    else:
        return res

def get_mean_resource_entropy(pe):
    resource_section = None
    for section in pe.sections:
        if section.Name.strip(b'\x00') == b'.rsrc':
            resource_section = section
            break
    if resource_section:
        entropies = []
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    offset = resource_lang.data.struct.OffsetToData
                    size = resource_lang.data.struct.Size
                    data = pe.get_memory_mapped_image()[offset:offset+size]
                    entropies.append(calculate_entropy(data))
        if entropies:
            mean_entropy = sum(entropies) / len(entropies)
            return mean_entropy
    return 0

def get_min_entropy(pe):
    resource_section = None
    min_entropy = float('inf')
    
    for section in pe.sections:
        if section.Name.strip(b'\x00') == b'.rsrc':
            resource_section = section
            break
            
    if resource_section:
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    offset = resource_lang.data.struct.OffsetToData
                    size = resource_lang.data.struct.Size
                    data = pe.get_memory_mapped_image()[offset:offset+size]
                    entropy = calculate_entropy(data)
                    min_entropy = min(min_entropy, entropy)
    
    if min_entropy == float('inf'):
        return 0
    else:
        return min_entropy

def get_max_entropy(pe):
    resource_section = None
    max_entropy = float('-inf')
    
    for section in pe.sections:
        if section.Name.strip(b'\x00') == b'.rsrc':
            resource_section = section
            break
            
    if resource_section:
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    offset = resource_lang.data.struct.OffsetToData
                    size = resource_lang.data.struct.Size
                    data = pe.get_memory_mapped_image()[offset:offset+size]
                    entropy = calculate_entropy(data)
                    max_entropy = max(max_entropy, entropy)
    
    if max_entropy == float('-inf'):
        return 0
    else:
        return max_entropy



def resources_mean_size(pe):
    resource_section = None
    for section in pe.sections:
        if section.Name.strip(b'\x00') == b'.rsrc':
            resource_section = section
            break
    if resource_section:
        reslen = 0
        size = 0
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    reslen += 1
                    size += resource_lang.data.struct.Size
        resMean = size / reslen
        return resMean
    else:
        return 0


def resources_min_size(pe):
    resource_section = None
    for section in pe.sections:
        if section.Name.strip(b'\x00') == b'.rsrc':
            resource_section = section
            break
    if resource_section:
        minSize = float('inf')
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    size = resource_lang.data.struct.Size
                    minSize = min(minSize, size)
        return minSize
    else:
        return 0


def resources_max_size(pe):
    resource_section = None
    for section in pe.sections:
        if section.Name.strip(b'\x00') == b'.rsrc':
            resource_section = section
            break
    if resource_section:
        maxSize = float('-inf')
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    size = resource_lang.data.struct.Size
                    maxSize = max(maxSize, size)
        return maxSize
    else:
        return 0


def get_load_config_size(pe):
    load_config_size = 0
    try:
        load_config = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']]
        load_config_size = load_config.Size
    except AttributeError:
        load_config_size = 0
    return load_config_size

def get_version_info_size(pe):
    version_info_size = 0
    try:
        version_info = pe.DIRECTORY_ENTRY_RESOURCE.entries[pefile.RESOURCE_TYPE['RT_VERSION']][0]
        version_info_size = version_info.directory.entries[0].data.struct.Size
    except (AttributeError, KeyError, IndexError):
        version_info_size = 0
    return version_info_size

size_of_uninitialized_data = pe.OPTIONAL_HEADER.SizeOfUninitializedData


model_features = {}
model_features["Machine"] = machine
model_features["SizeOfOptionalHeader"] = optional_header_size
model_features["Characteristics"] = characteristics
model_features["MajorLinkerVersion"] = major_linker_version
model_features["MinorLinkerVersion"] = minor_linker_version
model_features["SizeOfCode"] = size_of_code
model_features["SizeOfInitializedData"] = size_of_initialized_data
model_features["SizeOfUninitializedData"] = size_of_uninitialized_data
model_features["AddressOfEntryPoint"] = entry_point
model_features["BaseOfCode"] = base_of_code
model_features["BaseOfData"] = base_of_data
model_features["ImageBase"] = image_base
model_features["SectionAlignment"] = section_alignment
model_features["FileAlignment"] = file_alignment
model_features["MajorOperatingSystemVersion"] = major_os_ver
model_features["MinorOperatingSystemVersion"] = minor_os_ver
model_features["MajorImageVersion"] = major_img_ver
model_features["MinorImageVersion"] = minor_img_ver
model_features["MajorSubsystemVersion"] = major_subsys_ver
model_features["MinorSubsystemVersion"] = minor_subsys_ver
model_features["SizeOfImage"] = size_of_img
model_features["SizeOfHeaders"] = size_of_headers
model_features["CheckSum"] = checksum
model_features["Subsystem"] = subsys
model_features["DllCharacteristics"] = dll_characteristics
model_features["SizeOfStackReserve"] = size_of_stack_reserve
model_features["SizeOfStackCommit"] = size_of_stack_commit
model_features["SizeOfHeapReserve"] = size_of_heap_reserve
model_features["SizeOfHeapCommit"] = size_of_heap_commit
model_features["LoaderFlags"] = loader_flags
model_features["NumberOfRvaAndSizes"] = no_of_rva_sizes
model_features["SectionsNb"] = sectionsNb
model_features["SectionsMeanEntropy"] = mean_section_entropy(pe)
model_features["SectionsMinEntropy"] = min_section_entropy(pe)
model_features["SectionsMaxEntropy"] = max_section_entropy(pe)
model_features["SectionsMeanRawsize"] = sections_mean_rawsize(pe)
model_features["SectionsMinRawsize"] = sections_min_rawsize(pe)
model_features["SectionMaxRawsize"] = sections_max_rawsize(pe)
model_features["SectionsMeanVirtualsize"] = sections_mean_virtual_size(pe)
model_features["SectionsMinVirtualsize"] = sections_min_virtsize(pe)
model_features["SectionMaxVirtualsize"] = sections_max_virtsize(pe)
model_features["ImportsNbDLL"] = imports_count(pe)
model_features["ImportsNb"] = total_imports_count(pe)
model_features["ImportsNbOrdinal"] = ordinal_imports_count(pe)
model_features["ExportNb"] = exports_count(pe)
model_features["ResourcesNb"] = resources_count(pe)
model_features["ResourcesMeanEntropy"] = get_mean_resource_entropy(pe)
model_features["ResourcesMinEntropy"] = get_min_entropy(pe)
model_features["ResourcesMaxEntropy"] = get_max_entropy(pe)
model_features["ResourcesMeanSize"] = resources_mean_size(pe)
model_features["ResourcesMinSize"] = resources_min_size(pe)
model_features["ResourcesMaxSize"] = resources_max_size(pe)
model_features["LoadConfigurationSize"] = get_load_config_size(pe)
model_features["VersionInformationSize"] = get_version_info_size(pe)

'''
for k,v in model_features.items():
    print(f"{k}: {v}")
'''

import pickle
import os
import sys
if __name__ == '__main__':

    #Loading the classifier.pkl and features.pkl
    clf = pickle.loads(open(os.path.join('classifier.pkl'),'rb').read())
    features = pickle.loads(open(os.path.join('features2.pkl'),'rb').read())

    #extracting features from the PE file mentioned in the argument 
    data = model_features

    #matching it with the features saved in features.pkl
    pe_features = list(map(lambda x:data[x], features))
    print("Features used for classification: ", pe_features)

    #prediciting if the PE is malicious or not based on the extracted features
    res= clf.predict([pe_features])[0]
    print ('The file is %s' % (['malicious', 'legitimate'][res]))
