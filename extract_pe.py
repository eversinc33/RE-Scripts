import pefile

def extract_all_embedded_pes(parent_pe_path, output_base_path):
    # Load the parent PE
    parent_pe = pefile.PE(parent_pe_path)
    
    with open(parent_pe_path, 'rb') as f:
        parent_data = f.read()

    # Calculate the end of the parent PE's headers
    pe_header_end_offset = (parent_pe.DOS_HEADER.e_lfanew + 4 + 
                            parent_pe.FILE_HEADER.SizeOfOptionalHeader + 
                            len(parent_pe.sections) * 40)
    
    # Search for all MZ signatures after the original PE headers
    offset = pe_header_end_offset
    embedded_pe_count = 0

    while True:
        mz_offset = parent_data.find(b'MZ', offset)
        
        if mz_offset == -1:
            break
        
        try:
            # Read the potential embedded PE
            embedded_pe = parent_data[mz_offset:]
            embedded_pefile = pefile.PE(data=embedded_pe)

            # Write the embedded PE to a new file
            embedded_pe_count += 1
            output_path = f"{output_base_path}_{embedded_pe_count}.sys" # or exe
            with open(output_path, 'wb') as f:
                f.write(embedded_pe)
            
            print(f"[*] Embedded PE {embedded_pe_count} found at offset: {mz_offset}")
        
        except pefile.PEFormatError:
            pass

        # Move to the next byte after the current MZ signature
        offset = mz_offset + 2

    if embedded_pe_count == 0:
        print("No embedded PEs found")

parent_pe_path = "C:\Program Files\NoVirusThanks\Threat Killer\ThreatKiller.exe"
output_base_path = "NVTInj64"
extract_all_embedded_pes(parent_pe_path, output_base_path)
