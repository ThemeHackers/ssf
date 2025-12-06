from typing import Dict ,Any ,List 
from ssf.core .base import BaseScanner 
class ExtensionsScanner (BaseScanner ):
    KNOWN_EXTENSIONS ={
    "pg_stat_statements":{"risk":"LOW","details":"Query performance monitoring","check_schema":"extensions"},
    "pgcrypto":{"risk":"LOW","details":"Cryptographic functions","check_schema":"extensions"},
    "pgjwt":{"risk":"LOW","details":"JSON Web Token API","check_schema":"extensions"},
    "uuid-ossp":{"risk":"LOW","details":"UUID generation","check_schema":"extensions"},
    "citext":{"risk":"LOW","details":"Case-insensitive text type","check_type":"citext"},
    "hstore":{"risk":"LOW","details":"Key-value store","check_type":"hstore"},
    "intarray":{"risk":"LOW","details":"Integer array functions","check_schema":"extensions"},
    "ltree":{"risk":"LOW","details":"Hierarchical tree data structure","check_type":"ltree"},
    "pg_trgm":{"risk":"LOW","details":"Text similarity measurement","check_schema":"extensions"},
    "unaccent":{"risk":"LOW","details":"Text search dictionary","check_schema":"extensions"},
    "pgaudit":{"risk":"MEDIUM","details":"Audit logging (Check logs for sensitivity)","check_schema":"pgaudit"},
    "pg_safeupdate":{"risk":"SAFE","details":"Prevents unsafe updates/deletes","check_schema":"extensions"},
    "supautils":{"risk":"SAFE","details":"Supabase utility functions","check_schema":"supautils"},
    "supabase_vault":{"risk":"MEDIUM","details":"Secrets management (Vault schema exposed)","check_schema":"vault"},
    "pg_cron":{"risk":"HIGH","details":"Job scheduler (Check for unauthorized job creation)","check_schema":"cron"},
    "pg_repack":{"risk":"LOW","details":"Reorganize tables without locks","check_schema":"extensions"},
    "pg_partman":{"risk":"LOW","details":"Partition management","check_schema":"partman"},
    "auto_explain":{"risk":"LOW","details":"Automated query plan logging","check_schema":"extensions"},
    "hypopg":{"risk":"LOW","details":"Hypothetical indexes","check_schema":"hypopg"},
    "index_advisor":{"risk":"LOW","details":"Index recommendations","check_schema":"extensions"},
    "plv8":{"risk":"HIGH","details":"Javascript in SQL (Potential RCE/DoS if unchecked)","check_schema":"plv8"},
    "plpgsql_check":{"risk":"LOW","details":"PL/pgSQL linter","check_schema":"extensions"},
    "postgis":{"risk":"LOW","details":"Geospatial objects","check_type":"geography"},
    "postgis_raster":{"risk":"LOW","details":"PostGIS Raster support","check_schema":"extensions"},
    "postgis_tiger_geocoder":{"risk":"LOW","details":"US Census TIGER geocoder","check_schema":"tiger"},
    "postgis_topology":{"risk":"LOW","details":"PostGIS Topology","check_schema":"topology"},
    "address_standardizer":{"risk":"LOW","details":"Address parsing","check_schema":"extensions"},
    "wrappers":{"risk":"MEDIUM","details":"Foreign Data Wrappers (Check external connections)","check_schema":"wrappers"},
    "postgres_fdw":{"risk":"MEDIUM","details":"PostgreSQL FDW","check_schema":"extensions"},
    "pgvector":{"risk":"LOW","details":"Vector embeddings","check_type":"vector"},
    "rum":{"risk":"LOW","details":"RUM index (Inverted index)","check_schema":"extensions"},
    "fuse":{"risk":"LOW","details":"Fuzzy search","check_schema":"extensions"},
    "pg_net":{"risk":"HIGH","details":"Network requests (SSRF Risk)","check_schema":"net"},
    "pg_graphql":{"risk":"MEDIUM","details":"GraphQL API","check_schema":"graphql"},
    }
    async def scan (self ,openapi_spec :Dict [str ,Any ])->List [Dict [str ,Any ]]:
        self .log ("[*] Scanning for Database Extensions...","cyan")
        detected_extensions =[]
        definitions =openapi_spec .get ("definitions",{})
        for ext_name ,config in self .KNOWN_EXTENSIONS .items ():
            found =False 
            if "check_schema"in config :
                schema =config ["check_schema"]
                if self ._check_schema_exposure (definitions ,schema ):
                    found =True 
            if not found and "check_type"in config :
                dtype =config ["check_type"]
                if self ._check_type (definitions ,dtype ):
                    found =True 
            if found :
                detected_extensions .append ({
                "name":ext_name ,
                "risk":config ["risk"],
                "details":config ["details"]
                })
        if not any (e ["name"]=="pg_graphql"for e in detected_extensions ):
            try :
                r =await self .client .get ("/graphql/v1")
                if r .status_code !=404 :
                    detected_extensions .append ({
                    "name":"pg_graphql",
                    "risk":"MEDIUM",
                    "details":"GraphQL endpoint active (/graphql/v1)"
                    })
            except :
                pass 
        if detected_extensions :
            self .log (f"    [+] Detected {len (detected_extensions )} extensions.","green")
            for ext in detected_extensions :
                color ="red"if ext ["risk"]=="HIGH"else "yellow"if ext ["risk"]=="MEDIUM"else "blue"
                self .log (f"        - {ext ['name']}: {ext ['details']}",color )
        else :
            self .log ("    [-] No common extensions detected via public API.","dim")
        return detected_extensions 
    def _check_type (self ,definitions :Dict ,type_name :str )->bool :
        for def_name ,details in definitions .items ():
            for prop_name ,prop_details in details .get ("properties",{}).items ():
                if prop_details .get ("format")==type_name or prop_details .get ("type")==type_name :
                    return True 
        return False 
    def _check_schema_exposure (self ,definitions :Dict ,schema_name :str )->bool :
        for def_name in definitions .keys ():
            if def_name ==schema_name or def_name .startswith (f"{schema_name }."):
                return True 
        return False 