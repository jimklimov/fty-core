#
# Copyright (C) 2014-2015 Eaton
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#! \file    testlib-db.sh
#  \brief   library of functions and strings useful for database manipulation
#           specifically in $BIOS testing
#  \author  Michal Hrusecky <MichalHrusecky@Eaton.com>
#  \author  Jim Klimov <EvgenyKlimov@Eaton.com>
#  \author  Karol Hrdina <KarolHrdina@Eaton.com>
#  \author  Radomir Vrajik <RadomirVrajik@Eaton.com>
#  \details This is library of functions useful for $BIOS testing related to
#           databases, which can be sourced to interactive shell.
#           Generally it should not be included directly into a script because
#           it is sourced by weblib.sh along with testlib.sh; if you do need it
#           explicitly - include after scriptlib.sh, and after weblib.sh if you
#           want to use init_script*() which call accept_license().
#           Note: at least for now, many definitions relevant to database work
#           exist in other script-libraries because they first appeared there.
#           We may later choose to move them here, but it is not a priority.

# ***********************************************
### Database global variables
DB_LOADDIR="$CHECKOUTDIR/database/mysql"
DB_BASE="$DB_LOADDIR/initdb.sql"
DB_DATA="$DB_LOADDIR/load_data.sql"
DB_DATA_CURRENT="$DB_LOADDIR/current_data.sql"
DB_DATA_TESTREST="$DB_LOADDIR/load_data_test_restapi.sql"
export DB_LOADDIR DB_BASE DB_DATA

DB_TOPOP_NAME="power_topology.sql"
DB_TOPOP="$DB_LOADDIR/$DB_TOPOP_NAME"

DB_TOPOL_NAME="location_topology.sql"
DB_TOPOL="$DB_LOADDIR/$DB_TOPOL_NAME"

DB_RACK_POWER_NAME="rack_power.sql"
DB_RACK_POWER="$DB_LOADDIR/$DB_RACK_POWER_NAME"

DB_DC_POWER_NAME="dc_power.sql"
DB_DC_POWER="$DB_LOADDIR/$DB_DC_POWER_NAME"

DB_DC_POWER_UC1="$DB_LOADDIR/ci-DC-power-UC1.sql"
DB_CRUD="$DB_LOADDIR/crud_test.sql"
DB_OUTAGE="$DB_LOADDIR/test_outage.sql"
DB_ASSET_TAG_NOT_UNIQUE="$DB_LOADDIR/initdb_ci_patch.sql"

DB_AVERAGES="$DB_LOADDIR/test_averages.sql"
DB_AVERAGES_RELATIVE="$DB_LOADDIR/test_averages_relative.sql"

### Some pre-sets for CSV tests
CSV_LOADDIR="$CHECKOUTDIR/tests/fixtures/csv"
CSV_LOADDIR_BAM="$CSV_LOADDIR/bam"
CSV_LOADDIR_TPOWER="$CSV_LOADDIR/tpower"
CSV_LOADDIR_ASSIMP="$CSV_LOADDIR/asset_import"

### Directories where we can dump some output (mysqldump, temporary data, etc.)
DB_DUMP_DIR="$CHECKOUTDIR/tests/CI/web/log"     # TODO: change to BUILDSUBDIR
DB_TMPSQL_DIR="/tmp"
#DB_TMPSQL_DIR="$DB_DUMP_DIR"

### We also have to write exported temporary CSVs somewhere
CSV_TMP_DIR="$DB_DUMP_DIR"

### Expected results (saved in Git) are stored here:
DB_RES_DIR="$CHECKOUTDIR/tests/CI/web/results"

export DB_DUMP_DIR DB_TMPSQL_DIR DB_RES_DIR CSV_TMP_DIR
export CSV_LOADDIR CSV_LOADDIR_TPOWER CSV_LOADDIR_ASSIMP CSV_LOADDIR_BAM

### Killing connections as we recreate the database can help ensure that the
### old data would not survive and be referred to by subsequent tests which
### expect to start from a clean slate. But in practice some clients do die.
### Until we debug this to make them survive the database reconnections, the
### toggle defaults to "no". Even later it makes sense to keep this variable
### so we can have regression testing (that the ultimate fix works forever).
[ -z "${DB_KILL_CONNECTIONS-}" ] && DB_KILL_CONNECTIONS=no

do_killdb() {
    KILLDB_RES=0
    if [ -n "${DATABASE-}" ] ; then
        if [ x"$DB_KILL_CONNECTIONS" = xyes ]; then
            logmsg_warn "Trying to kill all connections to the ${DATABASE} database; some clients can become upset - it is their bug then!"
            sut_run 'mysql --disable-column-names -s -e "SHOW PROCESSLIST" | grep -vi PROCESSLIST | awk '"'\$4 ~ /$DATABASE/ {print \$1}'"' | while read P ; do mysqladmin kill "$P" || do_select "KILL $P" ; done' || KILLDB_RES=$?
        fi
        DATABASE=mysql do_select "DROP DATABASE if exists ${DATABASE}" || \
        sut_run "mysqladmin drop -f ${DATABASE}" || \
        { KILLDB_RES=$? ; logmsg_error "Failed to DROP DATABASE" ; }
        sleep 1
    else
        logmsg_warn "The DATABASE variable is not set, nothing known to DROP"
    fi
    DATABASE=mysql do_select "RESET QUERY CACHE" || \
        logmsg_warn "Failed to RESET QUERY CACHE"
    DATABASE=mysql do_select "FLUSH QUERY CACHE" || \
        logmsg_warn "Failed to FLUSH QUERY CACHE"
    sut_run "mysqladmin refresh ; sync; [ -w /proc/sys/vm/drop_caches ] && echo 3 > /proc/sys/vm/drop_caches && sync" || \
        logmsg_warn "Failed to FLUSH OS/VM CACHE"
    return $KILLDB_RES
}

killdb() {
    echo "CI-TESTLIB_DB - reset db: kill old DB ------------"
    KILLDB_OUT="`do_killdb 2>&1`"
    KILLDB_RES=$?
    if [ $KILLDB_RES != 0 ]; then
        logmsg_error "Hit some error while killing old database:"
        echo "==========================================="
        echo "$KILLDB_OUT"
        echo "==========================================="
    fi
    logmsg_debug "Database should have been dropped and caches should have been flushed at this point"
    return $KILLDB_RES
}

tarballdb_export() {
    # Saves a tarball of the database files (/var/lib/mysql) under $DB_DUMP_DIR
    # as "$1.tgz" file (fast gzip-1). The DB server should be stopped and FS
    # synced by this time, to be provided externally (by caller).
    # NOTE: It might be faster to pass traffic from ARM to X86 uncompressed,
    # and pack it on the test-driver machine. Now the tested system compresses
    # and network traffic is minimized (but ARM CPU is slower at this).
    # TODO: Perhaps implement a smarter logic here that would consider both
    # connectivity and (assumed) performance of the tested and testing systems.
    sut_run "cd /var/lib && tar cf - -I'gzip -1' mysql/" > "$DB_DUMP_DIR/$1.tgz"
}

tarballdb_import() {
    # Uses a tarball of the database files $DB_DUMP_DIR/$1.tgz to repopulate
    # /var/lib/mysql. The DB server should be stopped and FS synced by this
    # time, to be provided externally (by caller). Caller restarts server too.
    # NOTE: We do 'sync' the writes here, so the database server startup does
    # not time out because I/O is slow at that time. Testing showed that delays
    # are the same whether we sync explicitly or absorb writes during restart.
    sut_run "cd /var/lib && rm -rf mysql && tar xzf - && sync" < "$DB_DUMP_DIR/$1.tgz"
}

tarballdb_newer() (
    # Compares $DB_DUMP_DIR/$1.tgz timestamp to timestamps of SQL files listed
    # in $2..$N (relative to $DB_LOADDIR or using explicit full paths).
    # Returns 0 if the tarball exists and is newer than SQLs it was built from.
    # Returns 1 if tarball is absent; 2 if any SQL is found to be newer than
    # the tarball or the SQL files are not listed or at least one is not found
    # in practice.
    # Non-zero result means that tarball should be (re)created.
    # Only errors like absent args or files are reported, not discrepancies.
    _PWD="`pwd`"
    SQLS=""
    TGZ="$DB_DUMP_DIR/$1.tgz"
    [ -s "$TGZ" ] || return 1
    shift
    [ $# -eq 0 ] && logmsg_error "tarballdb_newer(): got an empty argument" && return 2
    while [ $# -gt 0 ]; do
        case "$1" in
            "") logmsg_error "tarballdb_newer(): got an empty argument"; return 2 ;;
            /*) SQLS="$SQLS $1" ;;
            ./*|../*) SQLS="$SQLS $_PWD/$1" ;;
            *)  # Short filename - assume relative to loaddir
                [ -n "$DB_LOADDIR" ] && [ -d "$DB_LOADDIR" ] || logmsg_warn "DB_LOADDIR='$DB_LOADDIR' not found"
                SQLS="$SQLS $DB_LOADDIR/$1"
                ;;
        esac
        shift
    done
    [ -z "$SQLS" ] && logmsg_error "tarballdb_newer(): got no SQLs" && return 2
    for F in $SQLS ; do
        [ -s "$F" ] || { logmsg_error "tarballdb_newer(): SQL file '$F' not found"; return 2; }
        OUT="`find "$F" -type f -newer "$TGZ"`" || return 2
        [ -n "$OUT" ] && return 2
    done
    # TGZ exists, all (1+) SQLs exist/findable, and none is newer than the TGZ
    return 0
)

do_loaddb_list() {
    if [ $# = 0 ] ; then
        logmsg_error "do_loaddb_list() called without arguments"
        return 1
    fi
    for data in "$@" ; do
        logmsg_info "Importing $data ..."
        loaddb_file "$data" || return $?
        logmsg_info "file $data applied OK"
    done
    return 0
}

loaddb_list() {
    LOADDB_OUT="`do_loaddb_list "$@" 2>&1`"
    LOADDB_RES=$?
    if [ $LOADDB_RES != 0 ]; then
        logmsg_error "Hit some error while importing database file(s):"
        echo "==========================================="
        echo "$LOADDB_OUT"
        echo "==========================================="
    else
        for data in "$@" ; do
            logmsg_info "file $data applied OK"
        done
    fi
    return $LOADDB_RES
}

loaddb_initial() {
    killdb || true      # Would fail the next step, probably
    echo "CI-TESTLIB_DB - reset db: (re-)initializing --------"
    loaddb_list "$DB_BASE" || return $?
    logmsg_debug "Database schema should have been initialized at this point: core schema file only"
    return 0
}

loaddb_sampledata() {
    loaddb_initial && \
    echo "CI-TESTLIB_DB - reset db: loading default sample data ----" && \
    loaddb_list "$DB_DATA" || return $?
    logmsg_debug "Database schema and data should have been initialized at this point: sample datacenter for tests"
    return 0
}

loaddb_default() {
    echo "CI-TESTLIB_DB - reset db: default REST API -------"
    loaddb_sampledata && \
    loaddb_list "$DB_DATA_TESTREST" || return $?
    logmsg_debug "Database schema and data should have been initialized at this point: for common REST API tests"
    return 0
}

loaddb_topo_loc() {
    echo "CI-TESTLIB_DB - reset db: topo-location ----------"
    loaddb_sampledata && \
    loaddb_list "$DB_TOPOL" || return $?
    logmsg_debug "Database schema and data should have been initialized at this point: for topology-location tests"
    return 0
}

loaddb_topo_pow() {
    echo "CI-TESTLIB_DB - reset db: topo-power -------------"
    loaddb_sampledata && \
    loaddb_list "$DB_TOPOP" || return $?
    logmsg_debug "Database schema and data should have been initialized at this point: for topology-power tests"
    return 0
}

loaddb_rack_power() {
    echo "CI-TESTLIB_DB - reset db: rack-power -------------"
    loaddb_initial || return $?
    for data in "$DB_RACK_POWER"; do
        logmsg_info "Importing $data ..."
        loaddb_file "$data" || return $?
    done
    logmsg_info "Database schema and data should have been initialized at this point: for rack-power tests"
    return 0
}

loaddb_dc_power_UC1() {
    echo "CI-TESTLIB_DB - reset db: dc-power-UC1 -------------"
    loaddb_initial || return $?
    for data in "$DB_DC_POWER_UC1"; do
        logmsg_info "Importing $data ..."
        loaddb_file "$data" || return $?
    done
    logmsg_info "Database schema and data should have been initialized at this point: for dc-power-UC1 tests"
    return 0
}

loaddb_dc_power() {
    echo "CI-TESTLIB_DB - reset db: dc-power ---------------"
    loaddb_initial || return $?
    for data in "$DB_DC_POWER"; do
        logmsg_info "Importing $data ..."
        loaddb_file "$data" || return $?
    done
    logmsg_info "Database schema and data should have been initialized at this point: for dc-power tests"
    return 0
}

loaddb_averages() {
    echo "CI-TESTLIB_DB - reset db: averages ---------------"
    loaddb_sampledata || return $?
    for data in "$DB_AVERAGES" "$DB_AVERAGES_RELATIVE"; do
        logmsg_info "Importing $data ..."
        loaddb_file "$data" || return $?
    done
    logmsg_info "Database schema and data should have been initialized at this point: for averages tests"
    return 0
}

loaddb_current() {
    echo "CI-TESTLIB_DB - reset db: current ----------------"
    loaddb_initial && \
    loaddb_list "$DB_DATA_CURRENT" || return $?
    logmsg_debug "Database schema and data should have been initialized at this point: for current tests"
    return 0
}

reloaddb_init_script_WRAPPER() {
    # Prepare sandbox for the test: ensure the database is freshly made
    # and licenses to not interfere; the accept_license() routine is
    # defined in weblib.sh at the moment.
    # As parameter(s) pass the loaddb_*() routine names to execute
    # while the database is down.
    reloaddb_stops_BIOS && \
    [ -x "$CHECKOUTDIR/tests/CI/ci-rc-bios.sh" ] && \
        echo "CI-TESTLIB_DB - reset db: stop BIOS ---------------" && \
        "$CHECKOUTDIR/tests/CI/ci-rc-bios.sh" --stop

    while [ $# -gt 0 ]; do
        $1 || return $?
        shift
    done

    reloaddb_stops_BIOS && \
    [ -x "$CHECKOUTDIR/tests/CI/ci-rc-bios.sh" ] && \
        echo "CI-TESTLIB_DB - reset db: start BIOS ---------------" && \
        { "$CHECKOUTDIR/tests/CI/ci-rc-bios.sh" --start-quick || return $? ; }

    # Some scripts only care about database and do not have weblib.sh included
    if type -t accept_license | grep -q 'shell function' ; then
        accept_license
        return $?
    fi
    return 0
}

init_script_initial(){
    reloaddb_init_script_WRAPPER loaddb_initial
}

init_script_sampledata(){
    reloaddb_init_script_WRAPPER loaddb_sampledata
}

init_script_default(){
    reloaddb_init_script_WRAPPER loaddb_default
}

init_script(){
    # Alias, legacy
    init_script_default "$@"
}

init_script_topo_loc(){
    reloaddb_init_script_WRAPPER loaddb_topo_loc
}

init_script_topo_pow(){
    reloaddb_init_script_WRAPPER loaddb_topo_pow
}

init_script_rack_power(){
    reloaddb_init_script_WRAPPER loaddb_rack_power
}

init_script_averages(){
    reloaddb_init_script_WRAPPER loaddb_averages
}

init_script_current(){
    reloaddb_init_script_WRAPPER loaddb_current
}

init_script_dc_power_UC1(){
    reloaddb_init_script_WRAPPER loaddb_dc_power_UC1
}

init_script_dc_power(){
    reloaddb_init_script_WRAPPER loaddb_dc_power
}

:

