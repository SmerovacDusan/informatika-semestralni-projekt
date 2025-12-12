import whois
import requests
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup

def virus_total_analysis(target):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto("https://www.virustotal.com/gui/home/url")
        page.fill('input#urlSearchInput', target)
        page.click('button#searchUrlButton')
        page.wait_for_timeout(6000)

        score = page.inner_text("div#positives") + page.inner_text("div#positives + div").strip()

        detections = []
        for engine in page.query_selector_all("span.engine-name"):
            engine_id = engine.get_attribute("id")
            if not engine_id:
                continue

            result_el = page.query_selector(f"span#{engine_id.replace('engine', 'engine-text')}")
            if not result_el:
                continue

            result = result_el.inner_text().strip()
            if result.lower() not in ["clean", "undetected", "harmless", "unrated"]:
                detections.append({
                    "vendor": engine.inner_text().strip(),
                    "result": result
                })

        browser.close()

        return {"score": score, "detections": detections}

def whois_analysis(target):
    try:
        return str(whois.whois(target))
    except Exception:
        return "NOT FOUND"

def where_goes_analysis(target):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto("https://wheregoes.com/")
        page.click('button:has-text("Agree")')
        page.fill('input#url', target)
        page.click('input#form_button')
        page.wait_for_timeout(5000)

        result_url = page.url
        browser.close()

    soup = BeautifulSoup(requests.get(result_url).content, "html.parser")

    where_goes_info = []
    for textarea in soup.find_all("textarea"):
        text = textarea.get_text().replace("|", "")
        if "http" in text:
            start = text.find("http")
            end = text.find("\n", start)
            if (end == -1): # end of line if there is no \n
                end = len(text)
            link = text[start:end].strip()
            if link not in where_goes_info:
                where_goes_info.append(link)

    return where_goes_info

def analysis(target, tools):
    # to be used in report generating
    virus_total_info = virus_total_analysis(target) if tools[0] else None
    whois_info = whois_analysis(target) if tools[1] else None
    where_goes_info = where_goes_analysis(target) if tools[3] else None