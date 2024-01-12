rule Detectar_Campana_Maliciosa_en_Navegadores {
    meta:
        description = "Detectar enlaces maliciosos relacionados con el robo de credenciales de Booking.com en los artefactos forenses de navegadores"

    strings:
    
      
		// Mensajes de gancho
		$gancho1 = "Documents" ascii wide nocase
		$gancho2 = "Passports" ascii wide nocase
		$gancho3 = "Allergy" ascii wide nocase
		$gancho4 = "Allergies" ascii wide nocase
		$gancho5 = "Health" ascii wide nocase
		$gancho6 = "Patient" ascii wide nocase
		$gancho7 = "test" ascii wide nocase
		
		//todos los mensajes tienen la palabra password
		
		$password = "password" ascii wide nocase

        // URLs de alojamiento de archivos maliciosos
        $url_google_drive = "drive.google.com" ascii wide nocase
        $url_dropbox = "dropbox.com" ascii wide nocase
        $url_mega = "mega.nz" ascii wide nocase
        $url_discord = /cdn\.discordapp\.com/ nocase

        // Patrones para Firefox
        $firefox_pattern = /places\.sqlite|cookies\.sqlite|webappsstore\.sqlite/ nocase

        // Patrones para Chrome
        $chrome_pattern = /History|Cookies|Login Data|Web Data/ nocase

        // Patrones para Edge
        $edge_pattern = /spartan\.edb|WebCacheV01\.dat/ nocase

        // Patrones para Safari
        $safari_pattern = /History\.db|Cookies\.binarycookies/ nocase

    condition:
        ($password and any of ($gancho*) and any of ($url_*)) and
        (
            $firefox_pattern or 
            $chrome_pattern or 
            $edge_pattern or 
            $safari_pattern
        )
}
