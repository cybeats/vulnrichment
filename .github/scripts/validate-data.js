// Validates data/<year>/CVE-<year>-<id>.json files and the commits that change them.
// Usage: node .github/scripts/validate-data.js                 every data file in HEAD
//        node .github/scripts/validate-data.js <base> <head>   files and commits that <head> adds to <base>
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const Ajv2020 = require('ajv/dist/2020');
const addFormats = require('ajv-formats');
const addErrors = require('ajv-errors');

const FILE_PATH = /^data\/(\d{4})\/(CVE-(\d{4})-\d{4,})\.json$/;
const ACTIONS = { A: 'add', M: 'modify', D: 'delete' };
const RANGE_KEYS = ['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'];

let errorCount = 0;
try {
    const [base, head] = process.argv.slice(2);
    if (base && !head) throw new Error('pass both <base> and <head>, or neither');
    if (base?.startsWith('-') || head?.startsWith('-')) throw new Error('refs must not start with "-"');
    process.chdir(path.join(__dirname, '..', '..'));

    // strictTypes/strictRequired off: the schema extends a shared CVSS definition and uses required inside not/anyOf
    const ajv = new Ajv2020({ allErrors: true, strict: true, strictTypes: false, strictRequired: false });
    addFormats(ajv);
    addErrors(ajv);
    const validate = ajv.compile(JSON.parse(fs.readFileSync('schemas/vulnrichment.schema.json', 'utf8')));

    // Every changed file except deletions, so a file turned into a symlink is checked too
    const ref = head ?? 'HEAD';
    const files = (base
        ? git(['diff', '--name-only', '-z', '--no-renames', '--diff-filter=d', `${base}...${head}`, '--', 'data/'])
        : git(['ls-tree', '-r', '-z', '--name-only', ref, '--', 'data/'])
    ).split('\0').filter(Boolean);
    const commits = base ? git(['rev-list', '--reverse', `${base}..${head}`]).split('\n').filter(Boolean) : [];

    for (const file of files) {
        const match = file.match(FILE_PATH);
        if (!match) {
            report(file, `Invalid path "${file}": expected data/<year>/CVE-<year>-<id>.json.`);
            continue;
        }
        const [, folderYear, cveId, cveYear] = match;
        if (folderYear !== cveYear) {
            report(file, `Invalid location "${file}": ${cveId} belongs in data/${cveYear}/.`);
            continue;
        }

        let record;
        try {
            // Stored bytes from git: a symlink gives its target path and is never followed; invalid UTF-8 and a BOM fail
            const bytes = git(['cat-file', 'blob', `${ref}:${file}`], 'buffer');
            record = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
        } catch (err) {
            report(file, `Invalid JSON in ${file}: ${err.message.trim()}`);
            continue;
        }

        if (!validate(record)) {
            for (const err of validate.errors) {
                const detail = err.params.additionalProperty ?? err.params.allowedValues?.join(', ') ?? err.params.allowedValue;
                report(file, `Schema error in ${file} at ${err.instancePath || '/'}: ${err.message}${detail === undefined ? '' : ` (${detail})`}.`);
            }
            continue;
        }
        if (record._annotation.cve_id !== cveId) {
            report(file, `Wrong cve_id in ${file}: "${record._annotation.cve_id}", expected "${cveId}".`);
        }

        // A cpeMatch with a version range must use * or - as the version in its criteria
        const nodes = record.cve.configurations.flatMap(configuration => configuration.nodes);
        while (nodes.length) {
            const node = nodes.pop();
            nodes.push(...(node.children ?? []));
            for (const cpe of node.cpeMatch ?? []) {
                const version = cpe.criteria.split(/(?<!\\):/)[5]; // "\:" is an escaped colon, not a separator
                if (RANGE_KEYS.some(key => key in cpe) && version !== '*' && version !== '-') {
                    report(file, `Invalid range in ${file}: ${cpe.criteria} has a fixed version, so it cannot have a version range.`);
                }
            }
        }
    }

    for (const sha of commits) {
        // --root: include a commit without parents; --cc: for a merge, only what the merge itself changed
        // (one status letter per parent); --no-renames: a rename is a delete plus an add; -z: exact file names
        const fields = git(['diff-tree', '-r', '--root', '--cc', '--no-renames', '--no-commit-id', '--name-status', '-z', sha]).split('\0').filter(Boolean);
        const statuses = fields.filter((_, i) => i % 2 === 0);
        const changed = fields.filter((_, i) => i % 2 === 1);
        if (!changed.some(name => name.startsWith('data/'))) continue;

        const subject = git(['log', '-1', '--format=%s', sha]).trim();
        const label = `Commit ${sha.slice(0, 7)} ("${subject}")`;
        const [status, file] = fields;
        const expected = `${ACTIONS[status]} ${path.posix.basename(file, path.posix.extname(file))}`;
        if (statuses.some(s => s.length > 1)) report(null, `${label} is a merge that changes ${changed.join(', ')} itself; make data changes in regular commits.`);
        else if (changed.length !== 1) report(null, `${label} changes ${changed.length} files; a commit must change exactly one (split a rename into a delete and an add).`);
        else if (!ACTIONS[status]) report(null, `${label} changes ${file} with unsupported git status ${status}.`);
        else if (subject !== expected) report(null, `${label} must have the message "${expected}".`);
    }

    console.log(`Validated ${files.length} file(s) and ${commits.length} commit(s): ${errorCount} error(s).`);
} catch (err) {
    report(null, `Validation could not run: ${err.message.trim()}`);
}
process.exitCode = errorCount ? 1 : 0;

// Workflow commands are lines starting with "::". Escaping % CR LF (and : , in the file property) stops
// pull request text, such as a JSON key containing a newline, from starting a command of its own.
function report(file, message) {
    errorCount++;
    const escape = text => text.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
    const property = file ? ` file=${escape(file).replace(/:/g, '%3A').replace(/,/g, '%2C')}` : '';
    console.log(`::error${property}::${escape(message)}`);
}

// Runs git directly with an argument list, never through a shell
function git(args, encoding = 'utf8') {
    return execFileSync('git', args, { encoding, maxBuffer: 100 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
}
