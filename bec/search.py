"""Exact typed indicator lookup in verified saved evidence, without collection or case writes."""
import html
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from . import __version__
from .comparison import Snapshot, _canonical_record, _read
from .google_events import normalize_child
from .normalize import normalize, records
from .storage import CaseError, GOOGLE_APPS, digest, encode, user_address


TYPES = ("email", "domain", "ip", "url", "sha256", "sha1")
FIELDS = {
    "email": {"entities.user[*]": "email_equals", "entities.mailbox[*]": "email_equals"},
    "domain": {"entities.user[*]": "email_domain_equals", "entities.mailbox[*]": "email_domain_equals",
               "entities.url[*]": "url_host_equals", "defender.Url": "url_host_equals",
               "defender.RemoteUrl": "url_host_equals", "defender.UrlDomain": "domain_field_equals"},
    "ip": {"entities.ip[*]": "ip_equals"},
    "url": {"entities.url[*]": "url_literal_equals", "defender.Url": "url_literal_equals",
            "defender.RemoteUrl": "url_literal_equals"},
    "sha256": {"entities.sha256[*]": "sha256_equals"},
    "sha1": {"entities.sha1[*]": "sha1_equals"},
}


def _domain(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Expected a domain name.")
    value = value[:-1] if value.endswith(".") else value
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Use the ip type for an IP literal.")
    value = value.encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                 for label in value.split(".")):
        raise ValueError("Expected a valid exact DNS domain name, without wildcards.")
    return value


def _email(value):
    value = user_address(value)
    local, domain = value.rsplit("@", 1)
    if any(character in local for character in '<>(),;:"[]'):
        raise ValueError("Use a simple email/UPN value without display names or quoted local parts.")
    return local + "@" + _domain(domain)


def _url(value):
    if not isinstance(value, str) or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                                         for character in value) or "\\" in value:
        raise ValueError("Use an absolute HTTP(S) URL without spaces or control characters.")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Use an absolute HTTP(S) URL.")
    parsed.port  # Validate malformed or out-of-range ports without resolving anything.
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        _domain(parsed.hostname)
    return value  # Full literal equality intentionally retains scheme/host case, path, query and fragment.


def canonical(kind, value):
    if kind == "email":
        return _email(value)
    if kind == "domain":
        return _domain(value)
    if kind == "url":
        return _url(value)
    if kind == "ip":
        if not isinstance(value, str) or "%" in value:
            raise ValueError("Use an IPv4/IPv6 address without a zone or CIDR suffix.")
        return str(ipaddress.ip_address(value))
    if kind in ("sha256", "sha1"):
        length = 64 if kind == "sha256" else 40
        if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{" + str(length) + "}", value):
            raise ValueError(f"{kind} requires exactly {length} hexadecimal characters.")
        return value.lower()
    raise ValueError("Unsupported indicator type.")


def _fields(event, kind):
    for path, relation in FIELDS[kind].items():
        section, key = path.split(".", 1)
        values = event.get(section, {}).get(key.removesuffix("[*]"))
        if path.endswith("[*]"):
            for index, value in enumerate(values if isinstance(values, list) else []):
                yield path.replace("[*]", f"[{index}]"), relation, value
        elif values is not None:
            yield path, relation, values


def _candidate(kind, relation, value):
    if relation == "email_domain_equals":
        return _email(value).rsplit("@", 1)[1]
    if relation == "url_host_equals":
        return _domain(urlsplit(_url(value)).hostname)
    return canonical(kind, value)


def search(directory, kind, value):
    """Search each canonical raw-record variant once and retain every original reference."""
    try:
        needle = canonical(kind, value)
    except (ValueError, TypeError, UnicodeError) as error:
        raise CaseError("Invalid " + kind + " indicator: " + str(error)) from error
    snapshot = Snapshot(directory)
    hits, field_coverage = [], {}
    cached_path, cached_rows = None, None
    for fingerprint, item in snapshot.inventory.items():
        dataset = item["dataset"]
        coverage = field_coverage.setdefault(dataset, dict(unique_records=0, normalized_observations=0,
            searchable_values=0, ignored_invalid_values=0, records_with_searchable_values=0, normalization_issues=0))
        coverage["unique_records"] += 1
        first = item["evidence"][0]
        path = snapshot.case.path / first["file"]
        if path != cached_path:
            raw = _read(path)
            if digest(raw) != first["sha256"]:
                raise CaseError("Evidence changed during indicator search: " + first["file"])
            cached_path, cached_rows = path, records(raw, dataset)
        row = _canonical_record(dataset, cached_rows[first["record_index"]])
        children = row.get("events") if dataset in GOOGLE_APPS and isinstance(row, dict) else None
        indexes = range(len(children)) if isinstance(children, list) and children else [None]
        observations, usable = [], False
        for index in indexes:
            try:
                event = (normalize_child(snapshot.case.tenant, dataset, row, index, first)
                         if dataset in GOOGLE_APPS else normalize(snapshot.case.tenant, dataset, row, first))
            except (ValueError, TypeError, IndexError, AttributeError, KeyError, OverflowError):
                coverage["normalization_issues"] += 1
                continue
            coverage["normalized_observations"] += 1
            matches = []
            for field, relation, observed in _fields(event, kind):
                try:
                    candidate = _candidate(kind, relation, observed)
                except (ValueError, TypeError, UnicodeError, AttributeError):
                    coverage["ignored_invalid_values"] += 1
                    continue
                usable = True
                coverage["searchable_values"] += 1
                if candidate == needle:
                    matches.append(dict(field=field, relation=relation, observed=observed, canonical_value=candidate))
            if matches:
                observations.append(dict(event_id=event["event_id"], event_type=event["event_type"],
                    timestamp_utc=event["timestamp_utc"], operation=event["operation"], actor=event["actor"],
                    target=event["target"], source_event_id=event["evidence"].get("source_event_id"),
                    matches=matches, evidence=[{**reference, **({"event_index": index} if index is not None else {})}
                                               for reference in item["evidence"]]))
        coverage["records_with_searchable_values"] += int(usable)
        if observations:
            hits.append(dict(record_fingerprint=fingerprint, dataset=dataset, native_identity=item["identity"],
                observations=observations, evidence=item["evidence"]))
    for dataset in snapshot.coverage:
        field_coverage.setdefault(dataset, dict(unique_records=0, normalized_observations=0, searchable_values=0,
            ignored_invalid_values=0, records_with_searchable_values=0, normalization_issues=0))
    snapshot.check_unchanged()
    limitations = [
        "No match means no exact typed value was found in the listed normalized fields of preserved evidence; it does not establish absence in the tenant.",
        "Search covers all preserved raw rows, including baseline and evidence outside the incident timeline scope. It does not collect or expand a case.",
        "Missing sources, failed queries, normalization issues, and unsupported or empty fields limit coverage.",
        "Subjects, bodies, filenames, arbitrary raw text, URL chains, attachments' binary contents, and unlisted fields are not searched.",
        "Domain relations require the exact domain/host. Subdomains and suffix/substring matches are not included.",
        "URL matching is literal and case-sensitive for the entire HTTP(S) URL, including path, query, encoding and fragment; no network lookup, decoding or Safe Links expansion occurs.",
        "Email matching follows BEC's case-insensitive normalized identity convention; matching metadata does not prove compromise, delivery, interaction or execution.",
    ]
    if not snapshot.binding["directory_id"] and snapshot.context["microsoft"]:
        limitations.append("Microsoft directory ID is unbound; this offline case relies on its analyst-supplied tenant alias. Native IDs present in evidence must still match case bindings.")
    return dict(format_version=1, bec_version=__version__, case=snapshot.metadata,
        query=dict(type=kind, value=value, canonical_value=needle), searched_fields=dict(FIELDS[kind]),
        summary=dict(matched_records=len(hits), matched_observations=sum(len(hit["observations"]) for hit in hits),
            source_references=sum(len(hit["evidence"]) for hit in hits), unique_records_examined=len(snapshot.inventory)),
        field_coverage=field_coverage, matches=sorted(hits, key=lambda hit: (hit["dataset"], hit["record_fingerprint"])),
        limitations=limitations)


def render_html(result):
    escape = lambda value: html.escape(str(value), quote=True)
    pretty = lambda value: "<pre>" + escape(json.dumps(value, ensure_ascii=False, indent=2)) + "</pre>"
    items = []
    for hit in result["matches"]:
        observations = []
        for event in hit["observations"]:
            references = "".join('<li><a href="' + escape(ref["uri"]) + '">' + escape(ref["file"]) +
                " row " + str(ref["record_index"]) + (" child " + str(ref["event_index"]) if "event_index" in ref else "") +
                "</a> (SHA-256 " + escape(ref["sha256"]) + ")</li>" for ref in event["evidence"])
            observations.append("<h3>" + escape(event["timestamp_utc"]) + " · " + escape(event["operation"]) + "</h3>" +
                pretty({key: value for key, value in event.items() if key != "evidence"}) + "<ul>" + references + "</ul>")
        items.append("<section><h2>" + escape(hit["dataset"]) + "</h2><p>Record fingerprint: " +
                     escape(hit["record_fingerprint"]) + "</p>" + "".join(observations) + "</section>")
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" "
        "content=\"width=device-width, initial-scale=1\"><title>BEC saved-case indicator search</title>"
        "<style>body{max-width:1100px;margin:2rem auto;padding:0 1rem;font:16px system-ui;line-height:1.5}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f7;padding:1rem}"
        "section{border:1px solid #ccd4dd;padding:1rem;margin:1rem 0}a,p{overflow-wrap:anywhere}</style>"
        "<h1>BEC saved-case indicator search</h1>" + pretty(result["query"]) + pretty(result["summary"]) +
        "<ul>" + "".join("<li>" + escape(note) + "</li>" for note in result["limitations"]) + "</ul>" +
        "<h2>Exact matched observations</h2>" + ("".join(items) or "<p>No exact match in the supported fields.</p>") +
        "<h2>Supported fields and match relations</h2>" + pretty(result["searched_fields"]) +
        "<h2>Field coverage</h2>" + pretty(result["field_coverage"]) +
        "<h2>Case binding and source coverage</h2>" + pretty(result["case"]) + "</html>")


def write_report(result, output, format_name):
    output = Path(output).resolve()
    if output.is_relative_to(Path(result["case"]["directory"])):
        raise CaseError("Search output must be outside the input case.")
    data = render_html(result).encode("utf-8") if format_name == "html" else encode(result)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(data)
    return output
