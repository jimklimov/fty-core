/*
 *
 * Copyright (C) 2017-2018 Eaton
 *
 * This software is confidential and licensed under Eaton Proprietary License
 * (EPL or EULA).
 *
 * This software is not authorized to be used, duplicated or disclosed to
 * anyone without the prior written permission of Eaton.
 * Limitations, restrictions and exclusions of the Eaton applicable standard
 * terms and conditions, such as its EPL and EULA, apply.
 *
 */

/*
 * @file    0019_discovery_monitoring_v2.sql
 * @brief   User preferences builtin data.
 */


/* For details on schema version support see the main initdb.sql */
SET @bios_db_schema_version = '201911290001';
SET @bios_db_schema_filename = '0019_discovery_monitoring_v2.sql';

use box_utf8;

/* This should be the first action in the SQL file */
START TRANSACTION;

DELIMITER //

DROP FUNCTION IF EXISTS BIN_TO_UUID;
CREATE FUNCTION BIN_TO_UUID(b BINARY(16))
RETURNS CHAR(36)
BEGIN
   DECLARE hexStr CHAR(32);
   SET hexStr = HEX(b);
   RETURN LOWER(CONCAT(
        SUBSTR(hexStr, 1, 8), '-',
        SUBSTR(hexStr, 9, 4), '-',
        SUBSTR(hexStr, 13, 4), '-',
        SUBSTR(hexStr, 17, 4), '-',
        SUBSTR(hexStr, 21)));
END //

DROP FUNCTION IF EXISTS UUID_TO_BIN;
CREATE FUNCTION UUID_TO_BIN(uuid CHAR(36))
RETURNS BINARY(16)
BEGIN
    RETURN UNHEX(REPLACE(uuid, '-', ''));
END //

DELIMITER ;

GRANT EXECUTE ON FUNCTION box_utf8.BIN_TO_UUID TO `bios-rw`@`localhost`;
GRANT EXECUTE ON FUNCTION box_utf8.UUID_TO_BIN TO `bios-rw`@`localhost`;

INSERT INTO t_bios_schema_version (tag, timestamp, filename, version) VALUES('begin-import', UTC_TIMESTAMP() + 0, @bios_db_schema_filename, @bios_db_schema_version);
/* Report the value */
SELECT * FROM t_bios_schema_version WHERE tag = 'begin-import' order by id desc limit 1;
COMMIT;

/* Security document type */
CREATE TABLE IF NOT EXISTS t_bios_secw_document_type(
    id_secw_document_type               VARCHAR(32) NOT NULL,
    PRIMARY KEY (id_secw_document_type)
);

INSERT IGNORE INTO t_bios_secw_document_type
(id_secw_document_type)
VALUES('Snmpv1'), ('Snmpv3'), ('UserAndPassword'), ('InternalCertificate'), ('ExternalCertificate');

/* Security document proxy object */
CREATE TABLE IF NOT EXISTS t_bios_secw_document(
    id_secw_document                    BINARY(16) NOT NULL,
    id_secw_document_type               VARCHAR(32) NOT NULL,
    PRIMARY KEY (id_secw_document),

    CONSTRAINT FK_SECW_DOCUMENT_SECW_DOCUMENT_TYPE
        FOREIGN KEY (id_secw_document_type)
        REFERENCES t_bios_secw_document_type (id_secw_document_type)
    ON DELETE RESTRICT
);

/* NUT configuration type */
CREATE TABLE IF NOT EXISTS t_bios_nut_configuration_type(
    id_nut_configuration_type           INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    configuration_name                  VARCHAR(255) NOT NULL,
    driver                              VARCHAR(255) NOT NULL,
    port                                VARCHAR(255) NOT NULL,
    PRIMARY KEY (id_nut_configuration_type)
);

INSERT IGNORE INTO t_bios_nut_configuration_type
(id_nut_configuration_type, configuration_name, driver, port)
VALUES
(1, 'Driver snmpv1 ups', 'snmp-ups', '${asset.ext.ip.1}'),
(2, 'Driver snmpv3 ups', 'snmp-ups', '${asset.ext.ip.1}'),
(3, 'Driver xmlv3 ups', 'netxml-ups', 'http://${asset.ext.ip.1}');

/* NUT configuration */
CREATE TABLE IF NOT EXISTS t_bios_nut_configuration(
    id_nut_configuration                INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
    id_nut_configuration_type           INTEGER UNSIGNED NOT NULL,
    id_asset_element                    INTEGER UNSIGNED NOT NULL,
    priority                            INTEGER UNSIGNED NOT NULL,
    is_enabled                          BOOLEAN NOT NULL,
    is_working                          BOOLEAN NOT NULL,
    PRIMARY KEY (id_nut_configuration),

    CONSTRAINT UNIQUE (id_asset_element, priority),

    CONSTRAINT FK_NUT_CONFIGURATION_NUT_CONFIGURATION_TYPE
        FOREIGN KEY (id_nut_configuration_type)
        REFERENCES t_bios_nut_configuration_type (id_nut_configuration_type)
    ON DELETE RESTRICT,

    CONSTRAINT FK_NUT_CONFIGURATION_BIOS_ASSET_ELEMENT
        FOREIGN KEY (id_asset_element)
        REFERENCES t_bios_asset_element (id_asset_element)
    ON DELETE CASCADE
);

/* Tuples of (NUT configuration; secw document) */
CREATE TABLE IF NOT EXISTS t_bios_nut_configuration_secw_document(
    id_nut_configuration                INTEGER UNSIGNED NOT NULL,
    id_secw_document                    BINARY(16) NOT NULL,
    PRIMARY KEY (id_nut_configuration, id_secw_document),

    CONSTRAINT FK_NUT_CONFIGURATION_SECW_DOCUMENT_SECW_DOCUMENT
        FOREIGN KEY (id_secw_document)
        REFERENCES t_bios_secw_document (id_secw_document)
    ON DELETE RESTRICT,

    CONSTRAINT FK_NUT_CONFIGURATION_SECW_DOCUMENT_NUT_CONFIGURATION
        FOREIGN KEY (id_nut_configuration)
        REFERENCES t_bios_nut_configuration (id_nut_configuration)
    ON DELETE CASCADE
);

/* List of secw documents requirements for a NUT configuration type */
CREATE TABLE IF NOT EXISTS t_bios_nut_configuration_type_secw_document_type_requirements(
    id_nut_configuration_type           INTEGER UNSIGNED NOT NULL,
    id_secw_document_type               VARCHAR(32) NOT NULL,
    PRIMARY KEY (id_nut_configuration_type, id_secw_document_type),

    CONSTRAINT FK_NUTCONFTYPE_SECWDOCTYPE_REQUIREMENTS_SECWDOCTYPE
        FOREIGN KEY (id_secw_document_type)
        REFERENCES t_bios_secw_document_type (id_secw_document_type)
    ON DELETE RESTRICT,

    CONSTRAINT FK_NUTCONFTYPE_SECWDOCTYPE_REQUIREMENTS_NUTCONFTYPE
        FOREIGN KEY (id_nut_configuration_type)
        REFERENCES t_bios_nut_configuration_type (id_nut_configuration_type)
    ON DELETE CASCADE
);

INSERT IGNORE INTO t_bios_nut_configuration_type_secw_document_type_requirements
(id_nut_configuration_type, id_secw_document_type)
VALUES
(1, 'Snmpv1'),
(2, 'Snmpv3');

/* NUT configuration attribute */
CREATE TABLE IF NOT EXISTS t_bios_nut_configuration_attribute(
    id_nut_configuration                INTEGER UNSIGNED NOT NULL,
    keytag                              VARCHAR(255) NOT NULL,
    value                               VARCHAR(255) NOT NULL,
    PRIMARY KEY (id_nut_configuration, keytag),

    CONSTRAINT FK_NUT_CONFIGURATION_ATTRIBUTE_NUT_CONFIGURATION
        FOREIGN KEY (id_nut_configuration)
        REFERENCES t_bios_nut_configuration (id_nut_configuration)
    ON DELETE CASCADE
);

/* NUT configuration default attribute */
CREATE TABLE IF NOT EXISTS t_bios_nut_configuration_default_attribute(
    id_nut_configuration_type               INTEGER UNSIGNED NOT NULL,
    keytag                                  VARCHAR(255) NOT NULL,
    value                                   VARCHAR(255) NOT NULL,
    PRIMARY KEY (id_nut_configuration_type, keytag),

    CONSTRAINT FK_NUTCONF_DEFAULT_ATTRIBUTE_NUT_CONFTYPE
        FOREIGN KEY (id_nut_configuration_type)
        REFERENCES t_bios_nut_configuration_type (id_nut_configuration_type)
    ON DELETE CASCADE
);

INSERT IGNORE INTO t_bios_nut_configuration_default_attribute
(id_nut_configuration_type, keytag, value)
VALUES
(2, 'snmp_version', 'v3');

/* NUT configuration default attribute view */
CREATE OR REPLACE VIEW v_conf_default_attribute AS
SELECT config.id_asset_element as id_asset_element, config.id_nut_configuration as id_nut_configuration, conf_def_attr.keytag as keytag, conf_def_attr.value as value, config.priority as priority, config.is_enabled as is_enabled, config.is_working as is_working
FROM t_bios_nut_configuration config
INNER JOIN t_bios_nut_configuration_default_attribute conf_def_attr
ON conf_def_attr.id_nut_configuration_type = config.id_nut_configuration_type
UNION SELECT config.id_asset_element as id_asset_element, config.id_nut_configuration as id_nut_configuration, 'driver' as keytag, confType.driver as value, config.priority as priority, config.is_enabled as is_enabled, config.is_working as is_working
FROM t_bios_nut_configuration_type confType JOIN t_bios_nut_configuration config
ON confType.id_nut_configuration_type = config.id_nut_configuration_type
UNION SELECT config.id_asset_element as id_asset_element, config.id_nut_configuration as id_nut_configuration, 'port' as keytag, confType.port as value, config.priority as priority, config.is_enabled as is_enabled, config.is_working as is_working
FROM t_bios_nut_configuration_type confType JOIN t_bios_nut_configuration config
ON confType.id_nut_configuration_type = config.id_nut_configuration_type
ORDER BY id_asset_element, priority, id_nut_configuration, keytag;

/* NUT configuration device attribute view */
CREATE OR REPLACE VIEW v_conf_device_attribute AS
SELECT config.id_asset_element as id_asset_element, config.id_nut_configuration as id_nut_configuration, conf_attr.keytag as keytag, conf_attr.value as value, config.priority as priority, config.is_enabled as is_enabled, config.is_working as is_working
FROM t_bios_nut_configuration config
INNER JOIN t_bios_nut_configuration_attribute conf_attr
ON conf_attr.id_nut_configuration = config.id_nut_configuration
ORDER BY id_asset_element, priority, id_nut_configuration, keytag;

/* NUT configuration attribute view */
CREATE OR REPLACE VIEW v_conf_attribute AS
SELECT * FROM v_conf_default_attribute
UNION
SELECT * FROM v_conf_device_attribute
ORDER BY id_asset_element, priority, id_nut_configuration, keytag;

/* This must be the last line of the SQL file */
START TRANSACTION;
INSERT INTO t_bios_schema_version (tag, timestamp, filename, version) VALUES('finish-import', UTC_TIMESTAMP() + 0, @bios_db_schema_filename, @bios_db_schema_version);
/* Report the value */
SELECT * FROM t_bios_schema_version WHERE tag = 'finish-import' order by id desc limit 1;
COMMIT;
