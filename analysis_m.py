import whois
import requests
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup

def analysis(target, tools):
    if (tools[0]):
        with sync_playwright() as p_virus_total:

            browser = p_virus_total.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto("https://www.virustotal.com/gui/home/url")
            page.fill('input[id="urlSearchInput"]', target)
            page.click('button[id="searchUrlButton"]')

            page.wait_for_timeout(5000)

            positives = page.inner_text("div#positives")
            total = page.inner_text("div#positives + div") # next div
            total = total.replace(" ", "")
            score = f"{positives}{total}"

            engines = page.query_selector_all("span.engine-name")

            detections = []
            for engine in engines:
                engine_id = engine.get_attribute("id")
                if not engine_id:
                    continue

                text_id = engine_id.replace("engine", "engine-text")
                detection_span = page.query_selector(f"span#{text_id}")
                if detection_span:
                    detection_text = detection_span.inner_text().strip()
                    # filters engines with malicious detection
                    if detection_text and detection_text.lower() not in ["clean", "undetected", "harmless", "unrated"]:
                        detections.append({
                            "vendor": engine.inner_text().strip(),
                            "result": detection_text
                        })

            browser.close()
            # to be used in report generating
            virus_total_info = {
                "score": score,
                "detections": detections
            }

    # whois
    if (tools[1]):
        whois_result = whois.whois(target)
        whois_result = str(whois_result)
        print(whois_result) # testing purposes
        # add code for report generating
    
    # where goes
    if (tools[3]):
        with sync_playwright() as p:

            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto("https://wheregoes.com/")

            page.click('button:has-text("Agree")') # accept cookies

            page.click('div[class="input-wrapper"]')

            page.fill('input[id="url"]', target)

            page.click('input[id="form_button"]')

            page.wait_for_timeout(5000)

            current_url = page.url
            browser.close()
            # add code for web scraping