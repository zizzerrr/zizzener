import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)"
]

visited = set()

def is_valid_url(url, base_netloc):
    try:
        parsed = urlparse(url)
        return (parsed.scheme in ['http', 'https']) and (parsed.netloc == base_netloc)
    except:
        return False

def get_forms(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["name"]:
            data[input["name"]] = payload
    try:
        if form_details["method"] == "post":
            res = requests.post(target_url, data=data, timeout=10)
        else:
            res = requests.get(target_url, params=data, timeout=10)
        return res
    except:
        return None

def scan_forms_xss(url):
    forms = get_forms(url)
    results = []
    for form in forms:
        form_details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            res = submit_form(form_details, url, payload)
            if res and payload in res.text:
                results.append({
                    "url": url,
                    "type": "form",
                    "payload": payload,
                    "form_action": form_details["action"],
                    "inputs": form_details["inputs"]
                })
    return results

def scan_url_params_xss(url):
    # فقط إذا فيه باراميتر
    if "?" not in url:
        return []
    results = []
    for payload in XSS_PAYLOADS:
        base, params = url.split("?", 1)
        test_url = base + "?" + params.replace("=", "=" + payload)
        try:
            res = requests.get(test_url, timeout=10)
            if payload in res.text:
                results.append({
                    "url": test_url,
                    "type": "url_param",
                    "payload": payload
                })
        except:
            continue
    return results

def crawl(url, base_netloc, max_depth=2, depth=0, report=None):
    if report is None:
        report = []
    if url in visited or depth > max_depth:
        return report
    visited.add(url)
    # فحص XSS
    report.extend(scan_forms_xss(url))
    report.extend(scan_url_params_xss(url))
    # تابع الزحف
    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        links = soup.find_all("a")
        for link in links:
            href = link.get("href")
            if href:
                full_url = urljoin(url, href)
                if is_valid_url(full_url, base_netloc):
                    crawl(full_url, base_netloc, max_depth, depth+1, report)
    except:
        pass
    return report

def scan_website(start_url):
    global visited
    visited = set()
    base_netloc = urlparse(start_url).netloc
    report = crawl(start_url, base_netloc)
    # ترتيب النتائج بحسب الرابط
    report_sorted = sorted(report, key=lambda x: x['url'])
    return {"findings": report_sorted, "total": len(report_sorted)}