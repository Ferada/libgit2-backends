/*
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * In addition to the permissions in the GNU General Public License,
 * the authors give you unlimited permission to link the compiled
 * version of this file into combinations with other programs,
 * and to distribute those combinations without any restriction
 * coming from the use of this file.  (The General Public License
 * restrictions do apply in other respects; for example, they cover
 * modification of the file, and distribution when not linked into
 * a combined executable.)
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "sqlite.h"

#include <assert.h>
#include <string.h>
#include <git2/sys/odb_backend.h>
#include <git2/sys/refdb_backend.h>
#include <git2/sys/refs.h>

#include <stdio.h>

#define GIT_TYPE_REF_OID '1'
#define GIT_TYPE_REF_SYMBOLIC '2'

typedef struct {
	git_odb_backend parent;
	sqlite3 *db;
	sqlite3_stmt *st_read;
	sqlite3_stmt *st_write;
	sqlite3_stmt *st_read_header;
	char close_db;
} sqlite_odb_backend;

typedef struct {
	git_refdb_backend parent;
	sqlite3 *db;
	sqlite3_stmt *st_read;
	sqlite3_stmt *st_read_all;
	sqlite3_stmt *st_write;
	sqlite3_stmt *st_delete;
	char close_db;
} sqlite_refdb_backend;

typedef struct {
	git_reference_iterator parent;
	size_t current;
	int nkeys;
	char **keys;
	sqlite_refdb_backend *backend;
} sqlite_refdb_iterator;

int sqlite_odb_backend__read_header(size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
	sqlite_odb_backend *backend;
	int error;

	assert(len_p && type_p && _backend && oid);

	backend = (sqlite_odb_backend *)_backend;
	error = GIT_ERROR;

	if (sqlite3_bind_text(backend->st_read_header, 1, (char *)oid->id, 20, SQLITE_TRANSIENT) == SQLITE_OK) {
		if (sqlite3_step(backend->st_read_header) == SQLITE_ROW) {
			*type_p = (git_otype)sqlite3_column_int(backend->st_read_header, 0);
			*len_p = (size_t)sqlite3_column_int(backend->st_read_header, 1);
			assert(sqlite3_step(backend->st_read_header) == SQLITE_DONE);
			error = GIT_OK;
		} else {
			error = GIT_ENOTFOUND;
		}
	}

	sqlite3_reset(backend->st_read_header);
	return error;
}

int sqlite_odb_backend__read(void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend, const git_oid *oid)
{
	sqlite_odb_backend *backend;
	int error;

	assert(data_p && len_p && type_p && _backend && oid);

	backend = (sqlite_odb_backend *)_backend;
	error = GIT_ERROR;

	if (sqlite3_bind_text(backend->st_read, 1, (char *)oid->id, 20, SQLITE_TRANSIENT) == SQLITE_OK) {
		if (sqlite3_step(backend->st_read) == SQLITE_ROW) {
			*type_p = (git_otype)sqlite3_column_int(backend->st_read, 0);
			*len_p = (size_t)sqlite3_column_int(backend->st_read, 1);
			*data_p = malloc(*len_p);

			if (*data_p == NULL) {
				giterr_set_oom();
				error = GIT_ERROR;
			} else {
				memcpy(*data_p, sqlite3_column_blob(backend->st_read, 2), *len_p);
				error = GIT_OK;
			}

			assert(sqlite3_step(backend->st_read) == SQLITE_DONE);
		} else {
			error = GIT_ENOTFOUND;
		}
	}

	sqlite3_reset(backend->st_read);
	return error;
}

int sqlite_odb_backend__read_prefix(git_oid *out_oid, void **data_p, size_t *len_p, git_otype *type_p, git_odb_backend *_backend,
					const git_oid *short_oid, size_t len) {
	if (len >= GIT_OID_HEXSZ) {
		/* Just match the full identifier */
		int error = sqlite_odb_backend__read(data_p, len_p, type_p, _backend, short_oid);
		if (error == GIT_OK)
			git_oid_cpy(out_oid, short_oid);

		return error;
	}
	/* not implemented (yet) */
	return GIT_ERROR;
}

int sqlite_odb_backend__exists(git_odb_backend *_backend, const git_oid *oid)
{
	sqlite_odb_backend *backend;
	int found;

	assert(_backend && oid);

	backend = (sqlite_odb_backend *)_backend;
	found = 0;

	if (sqlite3_bind_text(backend->st_read_header, 1, (char *)oid->id, 20, SQLITE_TRANSIENT) == SQLITE_OK) {
		if (sqlite3_step(backend->st_read_header) == SQLITE_ROW) {
			found = 1;
			assert(sqlite3_step(backend->st_read_header) == SQLITE_DONE);
		}
	}

	sqlite3_reset(backend->st_read_header);
	return found;
}

int sqlite_odb_backend__write(git_odb_backend *_backend, const git_oid *id, const void *data, size_t len, git_otype type)
{
	int error;
	sqlite_odb_backend *backend;

	assert(id && _backend && data);

	backend = (sqlite_odb_backend *)_backend;

	error = SQLITE_ERROR;

	if (sqlite3_bind_text(backend->st_write, 1, (char *)id->id, 20, SQLITE_TRANSIENT) == SQLITE_OK &&
		sqlite3_bind_int(backend->st_write, 2, (int)type) == SQLITE_OK &&
		sqlite3_bind_int(backend->st_write, 3, len) == SQLITE_OK &&
		sqlite3_bind_blob(backend->st_write, 4, data, len, SQLITE_TRANSIENT) == SQLITE_OK) {
		error = sqlite3_step(backend->st_write);
	}

	sqlite3_reset(backend->st_write);
	return (error == SQLITE_DONE) ? GIT_OK : GIT_ERROR;
}

void sqlite_odb_backend__free(git_odb_backend *_backend)
{
	sqlite_odb_backend *backend;
	assert(_backend);
	backend = (sqlite_odb_backend *)_backend;

	sqlite3_finalize(backend->st_read);
	sqlite3_finalize(backend->st_read_header);
	sqlite3_finalize(backend->st_write);

	if (backend->close_db)
		sqlite3_close(backend->db);

	free(backend);
}

int create_odb_table(sqlite3 *db)
{
	const char *sql_creat =
		"CREATE TABLE '" GIT2_ODB_TABLE_NAME "' ("
		"'oid' CHARACTER(20) PRIMARY KEY NOT NULL,"
		"'type' INTEGER NOT NULL,"
		"'size' INTEGER NOT NULL,"
		"'data' BLOB);";

	if (sqlite3_exec(db, sql_creat, NULL, NULL, NULL) != SQLITE_OK)
		return GIT_ERROR;

	return GIT_OK;
}

int init_odb_db(sqlite3 *db)
{
	const char *sql_check =
		"SELECT name FROM sqlite_master WHERE type='table' AND name='" GIT2_ODB_TABLE_NAME "';";

	sqlite3_stmt *st_check;
	int error;

	if (sqlite3_prepare_v2(db, sql_check, -1, &st_check, NULL) != SQLITE_OK)
		return GIT_ERROR;

	switch (sqlite3_step(st_check)) {
	case SQLITE_DONE:
		/* the table was not found */
		error = create_odb_table(db);
		break;

	case SQLITE_ROW:
		/* the table was found */
		error = GIT_OK;
		break;

	default:
		error = GIT_ERROR;
		break;
	}

	sqlite3_finalize(st_check);
	return error;
}

int init_odb_statements(sqlite_odb_backend *backend)
{
	const char *sql_read =
		"SELECT type, size, data FROM '" GIT2_ODB_TABLE_NAME "' WHERE oid = ?;";

	const char *sql_read_header =
		"SELECT type, size FROM '" GIT2_ODB_TABLE_NAME "' WHERE oid = ?;";

	const char *sql_write =
		"INSERT OR IGNORE INTO '" GIT2_ODB_TABLE_NAME "' VALUES (?, ?, ?, ?);";

	if (sqlite3_prepare_v2(backend->db, sql_read, -1, &backend->st_read, NULL) != SQLITE_OK)
		return GIT_ERROR;

	if (sqlite3_prepare_v2(backend->db, sql_read_header, -1, &backend->st_read_header, NULL) != SQLITE_OK)
		return GIT_ERROR;

	if (sqlite3_prepare_v2(backend->db, sql_write, -1, &backend->st_write, NULL) != SQLITE_OK)
		return GIT_ERROR;

	return GIT_OK;
}

int _git_odb_backend_sqlite(git_odb_backend **backend_out, sqlite3 *db, char close_db)
{
	sqlite_odb_backend *backend;
	int error;

	backend = calloc(1, sizeof(sqlite_odb_backend));
	if (backend == NULL) {
		giterr_set_oom();
		return GIT_ERROR;
	}

	error = init_odb_db(db);
	if (error < 0)
		goto cleanup;

	backend->db = db;
	backend->close_db = close_db;

	error = init_odb_statements(backend);
	if (error < 0)
		goto cleanup;

	backend->parent.version = GIT_ODB_BACKEND_VERSION;
	backend->parent.read = &sqlite_odb_backend__read;
	backend->parent.read_prefix = &sqlite_odb_backend__read_prefix;
	backend->parent.read_header = &sqlite_odb_backend__read_header;
	backend->parent.write = &sqlite_odb_backend__write;
	backend->parent.exists = &sqlite_odb_backend__exists;
	backend->parent.free = &sqlite_odb_backend__free;

	*backend_out = (git_odb_backend *)backend;
	return GIT_OK;

cleanup:
	sqlite_odb_backend__free((git_odb_backend *)backend);
	return error;
}

int git_odb_backend_sqlite_with_database(git_odb_backend **backend_out, sqlite3 *db)
{
	return _git_odb_backend_sqlite(backend_out, db, 0);
}

int git_odb_backend_sqlite(git_odb_backend **backend_out, const char *sqlite_db)
{
	sqlite3 *database;

	if (sqlite3_open(sqlite_db, &database) != SQLITE_OK)
		return GIT_ERROR;

	return _git_odb_backend_sqlite(backend_out, database, 1);
}

int sqlite_refdb_backend__exists(int *exists, git_refdb_backend *_backend, const char *ref_name)
{
	sqlite_refdb_backend *backend = (sqlite_refdb_backend *)_backend;

	assert(backend);

	*exists = 0;

	if (sqlite3_bind_text(backend->st_read, 1, (char *)ref_name, -1, SQLITE_TRANSIENT) == SQLITE_OK) {
		if (sqlite3_step(backend->st_read) == SQLITE_ROW) {
			*exists = 1;
			assert(sqlite3_step(backend->st_read) == SQLITE_DONE);
		}
	}

	sqlite3_reset(backend->st_read);
	return GIT_OK;
}

int sqlite_refdb_backend__lookup(git_reference **out, git_refdb_backend *_backend, const char *ref_name)
{
	sqlite_refdb_backend *backend;
	int error = GIT_OK;

	assert(ref_name && _backend);

	backend = (sqlite_refdb_backend *) _backend;

	if (sqlite3_bind_text(backend->st_read, 1, ref_name, strlen(ref_name), SQLITE_TRANSIENT) == SQLITE_OK) {
		if (sqlite3_step(backend->st_read) == SQLITE_ROW) {
			const unsigned char *raw_ref = sqlite3_column_text(backend->st_read, 0);
			if (raw_ref[0] == GIT_TYPE_REF_OID) {
				git_oid oid;
				git_oid_fromstr(&oid, raw_ref + 2);
				*out = git_reference__alloc(ref_name, &oid, NULL);
			} else if (raw_ref[0] == GIT_TYPE_REF_SYMBOLIC) {
				*out = git_reference__alloc_symbolic(ref_name, raw_ref + 2);
			} else {
				error = GIT_ERROR;
			}
			assert(sqlite3_step(backend->st_read) == SQLITE_DONE);
		} else {
			error = GIT_ENOTFOUND;
		}
	} else {
		error = GIT_ERROR;
	}

	sqlite3_reset(backend->st_read);
	return error;
}

void sqlite_refdb_backend__iterator_free(git_reference_iterator *_iter)
{
	sqlite_refdb_iterator *iter;
	assert(_iter);
	iter = (sqlite_refdb_iterator *) _iter;
	free(iter);
}

int sqlite_refdb_backend__iterator_next(git_reference **ref, git_reference_iterator *_iter)
{
	sqlite_refdb_iterator *iter;
	const char* ref_name;
	int error;

	assert(_iter);
	iter = (sqlite_refdb_iterator *) _iter;

	if (iter->current < iter->nkeys) {
		ref_name = iter->keys[iter->current++];
		error = sqlite_refdb_backend__lookup(ref, (git_refdb_backend *)iter->backend, ref_name);
		return error;
	}

	return GIT_ITEROVER;
}

int sqlite_refdb_backend__iterator_next_name(const char **ref_name, git_reference_iterator *_iter)
{
	sqlite_refdb_iterator *iter;

	assert(_iter);
	iter = (sqlite_refdb_iterator *) _iter;

	if (iter->current < iter->nkeys) {
		*ref_name = strdup(iter->keys[iter->current++]);
		return GIT_OK;
	}

	return GIT_ITEROVER;
}

int sqlite_refdb_backend__iterator(git_reference_iterator **_iter, struct git_refdb_backend *_backend, const char *glob)
{
	sqlite_refdb_backend *backend;
	sqlite_refdb_iterator *iterator;

	assert(_backend);

	backend = (sqlite_refdb_backend *) _backend;

	int error;
	sqlite3_stmt *stmt_read;
	char *stmt_str = "SELECT refname FROM " GIT2_REFDB_TABLE_NAME " WHERE refname LIKE 'refs/%';";
	if (glob != NULL) { // TODO: looks buggy as fuck
		stmt_str = strcpy(malloc(strlen(stmt_str) + strlen(glob) + 1), stmt_str);
		strcpy(stmt_str + strlen(stmt_str) - strlen("refs/%';"), glob);
		strcpy(stmt_str + strlen(stmt_str), "%';");
	}
	error = sqlite3_prepare_v2(backend->db, stmt_str, -1, &stmt_read, NULL);
	if (glob != NULL)
		free(stmt_str);

	if (error != SQLITE_OK) {
		sqlite3_finalize(stmt_read);
		return GIT_ERROR;
	}

	int nkeys = sqlite3_data_count(stmt_read);
	char **keys = malloc(nkeys * sizeof(char*));

	/* loop reading each row until step returns anything other than SQLITE_ROW */
	int result;
	int i = 0;
	do {
		result = sqlite3_step(stmt_read);
		if (result == SQLITE_ROW) {
			keys[i++] = strdup(sqlite3_column_text(stmt_read, 0));
		}
	} while (result == SQLITE_ROW);

	iterator = (sqlite_refdb_iterator *) calloc(1, sizeof(sqlite_refdb_iterator));

	iterator->backend = backend;
	iterator->nkeys = nkeys;
	iterator->keys = keys;

	iterator->parent.next = &sqlite_refdb_backend__iterator_next;
	iterator->parent.next_name = &sqlite_refdb_backend__iterator_next_name;
	iterator->parent.free = &sqlite_refdb_backend__iterator_free;

	*_iter = (git_reference_iterator *) iterator;

	return GIT_OK;
}

int sqlite_refdb_backend__write(
	git_refdb_backend *_backend,
	const git_reference *ref,
	int force,
	const git_signature *who,
	const char *message,
	const git_oid *old,
	const char *old_target)
{
	sqlite_refdb_backend *backend;

	const char *name = git_reference_name(ref);
	const git_oid *target;
	char oid_str[GIT_OID_HEXSZ + 1];

	assert(ref && _backend);

	backend = (sqlite_refdb_backend *) _backend;

	int result = sqlite3_bind_text(backend->st_write, 1, name, strlen(name), SQLITE_TRANSIENT);
	fprintf(stderr, "%d\n", result);

	if (result == SQLITE_OK) {
		target = git_reference_target(ref);
		char *write_value;
		if (target) {
			git_oid_nfmt(oid_str, sizeof(oid_str), target);
			write_value = malloc(2 + strlen(oid_str) + 1);
			write_value[0] = GIT_TYPE_REF_OID;
			write_value[1] = ':';
			strcpy(write_value + 2, oid_str);
		} else {
			const char *symbolic_target = git_reference_symbolic_target(ref);
			write_value = malloc(2 + strlen(symbolic_target) + 1);
			write_value[0] = GIT_TYPE_REF_SYMBOLIC;
			write_value[1] = ':';
			strcpy(write_value + 2, symbolic_target);
		}

		result = sqlite3_bind_text(backend->st_write, 2, write_value, strlen(write_value), SQLITE_TRANSIENT);
		if (result == SQLITE_OK) {
			result = sqlite3_step(backend->st_write);
		}
	}

	sqlite3_reset(backend->st_write);
	return (result == SQLITE_DONE) ? GIT_OK : GIT_ERROR;
}

int sqlite_refdb_backend__rename(
	git_reference **out,
	git_refdb_backend *_backend,
	const char *old_name,
	const char *new_name,
	int force,
	const git_signature *who,
	const char *message)
{
	sqlite_refdb_backend *backend;

	assert(old_name && new_name && _backend);

	backend = (sqlite_refdb_backend *) _backend;
	sqlite3_stmt *stmt;
	const char *stmt_str = "UPDATE " GIT2_REFDB_TABLE_NAME " SET refname = ? WHERE refname = ?;";

	if (sqlite3_prepare_v2(backend->db, stmt_str, -1, &stmt, NULL) != SQLITE_OK) {
		return GIT_ERROR;
	}

	int result = sqlite3_bind_text(stmt, 1, new_name, strlen(new_name), SQLITE_TRANSIENT);
	result &= sqlite3_bind_text(stmt, 2, old_name, strlen(old_name), SQLITE_TRANSIENT);

	if (result != SQLITE_OK) {
		return GIT_ERROR;
	}

	if (sqlite3_step(stmt) != SQLITE_OK) {
		sqlite3_finalize(stmt);
		return GIT_ERROR;
	}

	sqlite3_finalize(stmt);
	return sqlite_refdb_backend__lookup(out, (git_refdb_backend *)backend, new_name);
}

int sqlite_refdb_backend__del(git_refdb_backend *_backend, const char *ref_name, const git_oid *old, const char *old_target)
{
	sqlite_refdb_backend *backend;

	assert(ref_name && _backend);

	backend = (sqlite_refdb_backend *) _backend;

	int error = SQLITE_ERROR;
	if (sqlite3_bind_text(backend->st_delete, 1, ref_name, strlen(ref_name), SQLITE_TRANSIENT) == SQLITE_OK) {
		error = sqlite3_step(backend->st_delete);
	}

	sqlite3_reset(backend->st_delete);
	if (error == SQLITE_DONE) {
		return GIT_OK;
	}

	return GIT_ERROR;
}

void sqlite_refdb_backend__free(git_refdb_backend *_backend)
{
	sqlite_refdb_backend *backend;
	assert(_backend);
	backend = (sqlite_refdb_backend *)_backend;

	sqlite3_finalize(backend->st_read);
	sqlite3_finalize(backend->st_read_all);

	if (backend->close_db)
		sqlite3_close(backend->db);

	free(backend);
}

int sqlite_refdb_backend__has_log(git_refdb_backend *_backend, const char *name)
{
	return 0;
}

int sqlite_refdb_backend__ensure_log(git_refdb_backend *_backend, const char *name)
{
	return GIT_ERROR;
}

int sqlite_refdb_backend__reflog_read(git_reflog **out, git_refdb_backend *_backend, const char *name)
{
	return GIT_ERROR;
}

int sqlite_refdb_backend__reflog_write(git_refdb_backend *_backend, git_reflog *reflog)
{
	return GIT_ERROR;
}

int sqlite_refdb_backend__reflog_rename(git_refdb_backend *_backend, const char *old_name, const char *new_name)
{
	return GIT_ERROR;
}

int sqlite_refdb_backend__reflog_delete(git_refdb_backend *_backend, const char *name)
{
	return GIT_ERROR;
}

int create_refdb_table(sqlite3 *db)
{
	const char *sql_creat =
		"CREATE TABLE '" GIT2_REFDB_TABLE_NAME "' ("
		"'refname' TEXT PRIMARY KEY NOT NULL," // TODO: well this seems suspect
		"'ref' TEXT NOT NULL);"; // TODO: this too

	if (sqlite3_exec(db, sql_creat, NULL, NULL, NULL) != SQLITE_OK)
		return GIT_ERROR;

	return GIT_OK;
}

int init_refdb_db(sqlite3 *db)
{
	const char *sql_check =
		"SELECT name FROM sqlite_master WHERE type='table' AND name='" GIT2_REFDB_TABLE_NAME "';";

	sqlite3_stmt *st_check;
	int error;

	if (sqlite3_prepare_v2(db, sql_check, -1, &st_check, NULL) != SQLITE_OK)
		return GIT_ERROR;

	switch (sqlite3_step(st_check)) {
	case SQLITE_DONE:
		/* the table was not found */
		error = create_refdb_table(db);
		break;

	case SQLITE_ROW:
		/* the table was found */
		error = GIT_OK;
		break;

	default:
		error = GIT_ERROR;
		break;
	}

	sqlite3_finalize(st_check);
	return error;
}

int init_refdb_statements(sqlite_refdb_backend *backend)
{
	const char *sql_read =
		"SELECT ref FROM '" GIT2_REFDB_TABLE_NAME "' WHERE refname = ?;";

	const char *sql_read_all =
		"SELECT refname FROM '" GIT2_REFDB_TABLE_NAME "';";

	const char *sql_write =
		"INSERT OR REPLACE INTO " GIT2_REFDB_TABLE_NAME " VALUES (?, ?);";

	const char *sql_delete =
		"DELETE FROM " GIT2_REFDB_TABLE_NAME " WHERE refname = ?;";

	if (sqlite3_prepare_v2(backend->db, sql_read, -1, &backend->st_read, NULL) != SQLITE_OK)
		return GIT_ERROR;

	if (sqlite3_prepare_v2(backend->db, sql_read_all, -1, &backend->st_read_all, NULL) != SQLITE_OK)
		return GIT_ERROR;

	if (sqlite3_prepare_v2(backend->db, sql_write, -1, &backend->st_write, NULL) != SQLITE_OK)
		return GIT_ERROR;

	if (sqlite3_prepare_v2(backend->db, sql_delete, -1, &backend->st_delete, NULL) != SQLITE_OK)
		return GIT_ERROR;

	return GIT_OK;
}

int _git_refdb_backend_sqlite(git_refdb_backend **backend_out, sqlite3 *db, char close_db)
{
	sqlite_refdb_backend *backend;
	int error;

	backend = calloc(1, sizeof(sqlite_refdb_backend));
	if (backend == NULL) {
		giterr_set_oom();
		return GIT_ERROR;
	}

	error = init_refdb_db(db);
	if (error < 0)
		goto cleanup;

	backend->db = db;
	backend->close_db = close_db;

	error = init_refdb_statements(backend);
	if (error < 0)
		goto cleanup;

	backend->parent.version = GIT_REFDB_BACKEND_VERSION;
	backend->parent.exists = &sqlite_refdb_backend__exists;
	backend->parent.lookup = &sqlite_refdb_backend__lookup;
	backend->parent.iterator = &sqlite_refdb_backend__iterator;
	backend->parent.write = &sqlite_refdb_backend__write;
	backend->parent.del = &sqlite_refdb_backend__del;
	backend->parent.rename = &sqlite_refdb_backend__rename;
	backend->parent.compress = NULL;
	backend->parent.has_log = &sqlite_refdb_backend__has_log;
	backend->parent.ensure_log = &sqlite_refdb_backend__ensure_log;
	backend->parent.free = &sqlite_refdb_backend__free;
	backend->parent.reflog_read = &sqlite_refdb_backend__reflog_read;
	backend->parent.reflog_write = &sqlite_refdb_backend__reflog_write;
	backend->parent.reflog_rename = &sqlite_refdb_backend__reflog_rename;
	backend->parent.reflog_delete = &sqlite_refdb_backend__reflog_delete;

	*backend_out = (git_refdb_backend *)backend;
	return GIT_OK;

cleanup:
	sqlite_refdb_backend__free((git_refdb_backend *)backend);
	return error;
}

int git_refdb_backend_sqlite_with_database(git_refdb_backend **backend_out, sqlite3 *db)
{
	return _git_refdb_backend_sqlite(backend_out, db, 0);
}

int git_refdb_backend_sqlite(git_refdb_backend **backend_out, const char *sqlite_db)
{
	sqlite3 *database;

	if (sqlite3_open(sqlite_db, &database) != SQLITE_OK)
		return GIT_ERROR;

	return _git_refdb_backend_sqlite(backend_out, database, 1);
}
