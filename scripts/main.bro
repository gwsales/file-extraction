@load ./file-extensions

module FileExtraction;

export {
	## Path to store files
	const path: string = "" &redef;
	## Hook to include files in extraction
	global extract: hook(f: fa_file, meta: fa_metadata);
	## Hook to exclude files from extraction
	global ignore: hook(f: fa_file, meta: fa_metadata);
}

export {
    const mime_types_ignore: set[string] = {
        "application/ocsp-request",
        "application/ocsp-response",
        "application/x-x509-user-cert",
        "application/x-x509-ca-cert",
        };
}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	if ( meta?$mime_type && !hook FileExtraction::extract(f, meta) )
		{
		if ( !hook FileExtraction::ignore(f, meta) )
			return;

                if ( meta$mime_type in mime_types_ignore )
                        return;

		if ( meta$mime_type in mime_to_ext )
			local fext = mime_to_ext[meta$mime_type];
		else
			fext = split_string(meta$mime_type, /\//)[1];

		local fname = fmt("%s%s-%s.%s", path, f$source, f$id, fext);
		Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
			[$extract_filename=fname]);
		}
	}
