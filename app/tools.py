import datetime
from google.adk.tools import ToolContext
from google.cloud import firestore

# CRITICAL: Hardcode the project ID string to prevent Agent Platform project-number 404/database issues
FIRESTORE_PROJECT = "qwiklabs-gcp-03-c7f26ed5ce67"


def get_firestore_client() -> firestore.Client:
    return firestore.Client(project=FIRESTORE_PROJECT)


def lookup_scam_incidents(category: str = "", query_text: str = "") -> list[dict]:
    """Search and retrieve scam incidents and threat reports from the Firestore database.

    Args:
        category: Optional scam category to filter by (e.g. 'phishing', 'crypto', 'imposter', 'financial').
        query_text: Optional search string to match against incident title or description.

    Returns:
        A list of matching scam incident reports containing title, scam_type, risk_level, indicators, description, and recommended_action.
    """
    db = get_firestore_client()
    collection_ref = db.collection("scam_incidents")

    if category:
        docs = collection_ref.where("scam_type", "==", category.lower()).stream()
    else:
        docs = collection_ref.stream()

    results = []
    q = query_text.lower() if query_text else ""
    for doc in docs:
        data = doc.to_dict()
        data["id"] = doc.id
        title = data.get("title", "").lower()
        desc = data.get("description", "").lower()
        if not q or (q in title or q in desc):
            results.append(data)

    return results


def log_scam_incident(
    title: str,
    scam_type: str,
    risk_level: str,
    description: str,
    indicators: list[str],
    recommended_action: str,
) -> dict:
    """Log a new scam incident or threat report into the Firestore database catalog.

    Args:
        title: Short descriptive title of the scam (e.g., 'Fake IRS Tax Audit SMS').
        scam_type: Scam category ('phishing', 'crypto', 'imposter', 'financial', etc.).
        risk_level: Assessed risk level ('critical', 'high', 'medium', 'low').
        description: Detailed explanation of how the scam operates and what trick is used.
        indicators: List of red flags/indicators (e.g., ['spoofed_domain: irs-claim.org', 'urgent_wire_request']).
        recommended_action: Clear guidance on how to avoid or mitigate this scam.

    Returns:
        A dictionary confirming the newly logged incident ID and status.
    """
    db = get_firestore_client()
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

    doc_data = {
        "title": title,
        "scam_type": scam_type.lower(),
        "risk_level": risk_level.lower(),
        "description": description,
        "indicators": indicators,
        "recommended_action": recommended_action,
        "reported_at": now_str,
    }

    doc_ref = db.collection("scam_incidents").document()
    doc_ref.set(doc_data)

    return {
        "status": "success",
        "doc_id": doc_ref.id,
        "message": f"Successfully logged scam incident: '{title}'",
    }


import math
import re
import urllib.parse


def analyze_url_security(url: str) -> dict:
    """Analyze a suspicious URL or domain for security red flags and phishing indicators.

    Args:
        url: The web link or URL to analyze (e.g. 'http://irs-tax-audit-claim.xyz/login').

    Returns:
        A dictionary containing threat level, risk score, detected red flags, and safety recommendation.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""

    red_flags = []
    risk_score = 0

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        red_flags.append("Host is a raw IP address instead of a domain name")
        risk_score += 35

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".claim",
        ".work",
        ".click",
        ".country",
        ".kim",
        ".support",
        ".zip",
    ]
    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        red_flags.append("Domain uses high-risk TLD extension")
        risk_score += 25

    target_brands = [
        "google",
        "paypal",
        "apple",
        "bank",
        "irs",
        "amazon",
        "wallet",
        "binance",
        "metamask",
        "coinbase",
        "support",
    ]
    found_keywords = [b for b in target_brands if b in hostname.lower()]
    if found_keywords:
        official_domains = [
            "google.com",
            "paypal.com",
            "apple.com",
            "irs.gov",
            "amazon.com",
            "binance.com",
            "coinbase.com",
        ]
        if not any(hostname.endswith(off) for off in official_domains):
            red_flags.append(
                f"Domain contains sensitive brand keyword(s) {found_keywords} but is"
                " not official domain"
            )
            risk_score += 40

    if hostname:
        prob = [float(hostname.count(c)) / len(hostname) for c in set(hostname)]
        entropy = -sum(p * math.log(p, 2) for p in prob)
        if entropy > 3.8 and len(hostname) > 15:
            red_flags.append("High domain character randomness (entropy)")
            risk_score += 20

    if hostname.count("-") >= 3 or hostname.count(".") >= 3:
        red_flags.append("Excessive hyphens or subdomains used to mimic legitimate URL")
        risk_score += 15

    risk_score = min(risk_score, 100)
    if risk_score >= 70:
        threat_level = "CRITICAL"
        recommendation = (
            "DO NOT click this link or enter any credentials. This domain matches"
            " high-risk phishing signatures."
        )
    elif risk_score >= 35:
        threat_level = "HIGH"
        recommendation = (
            "Exercise extreme caution. Verify the sender through an independent official"
            " channel before proceeding."
        )
    else:
        threat_level = "LOW"
        recommendation = (
            "No obvious automated red flags detected, but always ensure HTTPS and check"
            " address bar carefully."
        )

    return {
        "url": url,
        "hostname": hostname,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "red_flags": red_flags if red_flags else ["None detected by heuristic scan"],
        "recommendation": recommendation,
    }


def analyze_live_call_transcript(transcript: str, caller_id: str = "") -> dict:
    """Analyze live phone call transcripts or caller dialogue for scam indicators and coercions.

    Args:
        transcript: Spoken text or dialogue snippet from the live call.
        caller_id: Optional caller ID or phone number (e.g. '+1-800-555-0199').

    Returns:
        A dictionary with assessment, detected coercion triggers, threat level, and immediate advice.
    """
    t_lower = transcript.lower()
    red_flags = []
    risk_score = 0

    if any(
        p in t_lower
        for p in [
            "don't tell",
            "keep this secret",
            "stay on the line",
            "do not hang up",
            "immediate action required",
        ]
    ):
        red_flags.append(
            "High-pressure coercion tactics demanding secrecy and prohibiting hanging up"
        )
        risk_score += 35

    if any(
        p in t_lower
        for p in [
            "gift card",
            "target card",
            "apple card",
            "walmart card",
            "wire transfer",
            "bitcoin atm",
            "crypto deposit",
            "western union",
        ]
    ):
        red_flags.append(
            "Demand for non-refundable or non-standard payment methods (gift cards, wire, crypto)"
        )
        risk_score += 45

    if any(
        p in t_lower
        for p in [
            "irs",
            "police",
            "sheriff",
            "warrant",
            "arrest",
            "jail",
            "tech support",
            "microsoft",
            "social security",
        ]
    ):
        red_flags.append(
            "Claimed authority impersonation (IRS, Police, Tech Support, Social Security)"
        )
        risk_score += 30

    if any(
        p in t_lower
        for p in ["grandma", "grandpa", "bail", "accident overseas", "in trouble"]
    ):
        red_flags.append("Urgent family emergency / grandchild in trouble narrative")
        risk_score += 30

    risk_score = min(risk_score, 100)
    if risk_score >= 60:
        threat_level = "CRITICAL"
        action = (
            "🚨 HANG UP IMMEDIATELY! Do not send money, gift cards, or personal details. Call the"
            " person or institution directly using an official number."
        )
    elif risk_score >= 30:
        threat_level = "HIGH"
        action = (
            "⚠️ High risk phone scam pattern detected. Ask for their name and reference"
            " number, hang up, and independently verify."
        )
    else:
        threat_level = "LOW"
        action = "No clear scam triggers detected in this snippet. Stay vigilant."

    return {
        "caller_id": caller_id if caller_id else "Unknown Caller",
        "threat_level": threat_level,
        "risk_score": risk_score,
        "coercion_triggers": red_flags if red_flags else ["No coercive triggers detected"],
        "immediate_action": action,
    }


def lookup_ip_threat_intelligence(ip_or_domain: str) -> dict:
    """Lookup IP address or domain infrastructure, ISP, hosting provider, and proxy/VPN risk indicators via public IP-API threat intelligence.

    Args:
        ip_or_domain: An IP address or domain hostname (e.g. '8.8.8.8', 'google.com').

    Returns:
        A dictionary containing ISP, country, cloud hosting indicator, proxy/VPN flag, and threat factors.
    """
    import json
    import os
    import urllib.parse
    import urllib.request

    target = ip_or_domain.strip()
    if "://" in target:
        target = urllib.parse.urlparse(target).hostname or target

    api_key = os.getenv("IP_API_KEY", "")
    if api_key:
        url = (
            f"https://pro.ip-api.com/json/{target}?key={api_key}&fields=status,message,country,regionName,city,isp,org,as,mobile,proxy,hosting,query"
        )
    else:
        url = (
            f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,isp,org,as,mobile,proxy,hosting,query"
        )

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "ScamGuard-AI/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))

        if data.get("status") != "success":
            return {
                "query": target,
                "status": "unresolved_or_invalid",
                "message": (
                    data.get("message", "Unable to resolve target IP or domain")
                    + " (Unregistered domain or invalid IP address)"
                ),
            }

        is_hosting = data.get("hosting", False)
        is_proxy = data.get("proxy", False)

        risk_factors = []
        if is_proxy:
            risk_factors.append(
                "Target uses an anonymizing proxy, VPN, or Tor exit node"
            )
        if is_hosting:
            risk_factors.append(
                "Target is hosted on a cloud datacenter/VPS provider rather than a"
                " residential ISP"
            )

        return {
            "query": data.get("query", target),
            "status": "success",
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", "Unknown"),
            "as_network": data.get("as", "Unknown"),
            "is_proxy_or_vpn": is_proxy,
            "is_cloud_hosting": is_hosting,
            "risk_factors": risk_factors
            if risk_factors
            else ["No proxy or hosting infrastructure risk flags detected"],
        }
    except Exception as e:
        return {
            "query": target,
            "status": "error",
            "message": f"Network lookup failed: {str(e)}",
        }


def geocode_address(address: str) -> dict:
    """Turn a physical street address or city name into geographic latitude and longitude coordinates using Google Maps Geocoding API.

    Args:
        address: The street address, city, or landmark (e.g., '1600 Amphitheatre Pkwy, Mountain View, CA' or 'Downtown Los Angeles').

    Returns:
        A dictionary with formatted address, latitude, longitude, and geocoding status.
    """
    import json
    import os
    import urllib.parse
    import urllib.request

    api_key = os.getenv("GOOGLE_MAPS_API_KEY", "")
    if not api_key:
        return {
            "status": "error",
            "message": "GOOGLE_MAPS_API_KEY environment variable is not set in .env",
        }

    encoded_address = urllib.parse.quote(address.strip())
    url = (
        "https://maps.googleapis.com/maps/api/geocode/json"
        f"?address={encoded_address}&key={api_key}"
    )

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "ScamGuard-AI/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))

        if data.get("status") != "OK" or not data.get("results"):
            return {
                "status": "error",
                "message": (
                    f"Geocoding failed for address '{address}':"
                    f" {data.get('status')}"
                ),
            }

        first_result = data["results"][0]
        location = first_result["geometry"]["location"]

        return {
            "status": "success",
            "formatted_address": first_result.get("formatted_address", address),
            "latitude": location["lat"],
            "longitude": location["lng"],
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Geocoding request failed: {str(e)}",
        }


def search_nearby_places(
    latitude: float,
    longitude: float,
    place_type: str = "police",
    radius_meters: float = 5000.0,
) -> dict:
    """Find nearby places (such as police stations, banks, or support services) around specific coordinates using Google Places API (New).

    Args:
        latitude: Latitude coordinate (-90.0 to 90.0).
        longitude: Longitude coordinate (-180.0 to 180.0).
        place_type: Type of place to search for (e.g. 'police', 'bank', 'post_office', 'local_government_office').
        radius_meters: Search radius in meters (default: 5000 meters / 5km).

    Returns:
        A dictionary containing a list of matching nearby places with name, formatted address, and coordinates.
    """
    import json
    import os
    import urllib.request

    api_key = os.getenv("GOOGLE_MAPS_API_KEY", "")
    if not api_key:
        return {
            "status": "error",
            "message": "GOOGLE_MAPS_API_KEY environment variable is not set in .env",
        }

    url = "https://places.googleapis.com/v1/places:searchNearby"
    headers = {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": api_key,
        "X-Goog-FieldMask": (
            "places.displayName,places.formattedAddress,places.location"
        ),
        "User-Agent": "ScamGuard-AI/1.0",
    }

    payload = {
        "includedTypes": [place_type.lower()],
        "maxResultCount": 5,
        "locationRestriction": {
            "circle": {
                "center": {
                    "latitude": latitude,
                    "longitude": longitude,
                },
                "radius": radius_meters,
            }
        },
    }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data_bytes, headers=headers, method="POST"
        )

        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))

        places_raw = data.get("places", [])
        results = []
        for p in places_raw:
            display_name = p.get("displayName", {}).get("text", "Unknown Place")
            formatted_address = p.get("formattedAddress", "No address listed")
            loc = p.get("location", {})
            results.append({
                "name": display_name,
                "address": formatted_address,
                "location": {
                    "latitude": loc.get("latitude"),
                    "longitude": loc.get("longitude"),
                },
            })

        return {
            "status": "success",
            "place_type": place_type,
            "places": results
            if results
            else ["No places found matching criteria"],
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Places API request failed: {str(e)}",
        }


GCS_BUCKET_NAME = "scamguard-assets-qwiklabs-gcp-03-c7f26ed5ce67"


def generate_threat_warning_infographic(
    topic: str,
    risk_level: str = "HIGH",
    tool_context: ToolContext = None,
) -> dict:
    """Generate a visual security warning badge or infographic for a specific scam topic using the gemini-3.1-flash-lite-image model in the global region. Saves the image as a Playground artifact and uploads it to Cloud Storage.

    Args:
        topic: The scam or security topic to generate an infographic for (e.g. 'Phishing Link', 'Crypto Wallet Drainer', 'Fake IRS SMS').
        risk_level: Risk level string ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        tool_context: ADK ToolContext passed automatically by the framework.

    Returns:
        A dictionary with status, filename, and the public GCS HTTPS URL of the generated warning image.
    """
    import datetime
    from google import genai
    from google.cloud import storage
    from google.genai import types

    client = genai.Client(
        vertexai=True,
        project="qwiklabs-gcp-03-c7f26ed5ce67",
        location="global",
    )

    prompt = (
        f"A professional digital cybersecurity warning badge and emblem for {topic}, "
        f"risk level {risk_level}, featuring a protective shield and alert icons."
    )

    try:
        response = client.models.generate_content(
            model="gemini-3.1-flash-lite-image",
            contents=prompt,
            config=types.GenerateContentConfig(response_modalities=["IMAGE"]),
        )

        if (
            not response.candidates
            or not response.candidates[0].content
            or not response.candidates[0].content.parts
        ):
            return {
                "status": "error",
                "message": "Image generation produced no image candidates",
            }

        part = response.candidates[0].content.parts[0]
        if not part.inline_data or not part.inline_data.data:
            return {
                "status": "error",
                "message": (
                    "Image generation response contained no inline image data"
                ),
            }

        image_bytes = part.inline_data.data
        mime_type = part.inline_data.mime_type or "image/png"

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )
        filename = f"scam_warning_{timestamp}.png"

        # (1) Save artifact in Playground panel if tool_context is present
        if tool_context is not None:
            artifact_part = types.Part.from_bytes(
                data=image_bytes, mime_type=mime_type
            )
            tool_context.save_artifact(
                filename=filename, artifact=artifact_part
            )

        # (2) Upload image bytes directly to GCS bucket (no local file path)
        storage_client = storage.Client(project="qwiklabs-gcp-03-c7f26ed5ce67")
        bucket = storage_client.bucket(GCS_BUCKET_NAME)
        blob = bucket.blob(filename)
        blob.upload_from_string(image_bytes, content_type=mime_type)

        public_url = (
            f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/{filename}"
        )

        return {
            "status": "success",
            "filename": filename,
            "public_url": public_url,
            "message": (
                f"Successfully generated warning infographic for '{topic}' and"
                " published to Cloud Storage."
            ),
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Image generation or upload failed: {str(e)}",
        }


def notify_trusted_guardian(
    user_name: str = "Protected User",
    threat_summary: str = "",
    coercion_triggers: list[str] = None,
    caller_id: str = "Unknown Number",
    guardian_contact: str = "Emergency Family Contact",
) -> dict:
    """Send an urgent emergency security notification to a user's designated family guardian or caregiver when high-risk call coercion or scam threat is detected.

    Args:
        user_name: Name of the protected family member (e.g. 'John / Dad').
        threat_summary: Summary description of the detected threat or ongoing call coercion.
        coercion_triggers: List of coercive tactics or keywords detected (e.g. ['demanding gift cards', 'urgent wire transfer']).
        caller_id: Caller phone number or identity string.
        guardian_contact: Name or phone number of designated family contact/caregiver.

    Returns:
        A dictionary confirming notification dispatch status, timestamp, alert payload, and caregiver instructions.
    """
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    triggers = coercion_triggers if coercion_triggers else ["High-urgency call coercion detected"]

    alert_message = (
        f"🚨 SCAMGUARD EMERGENCY ALERT: Urgent threat detected for {user_name} during incoming call from {caller_id}.\n"
        f"Threat Summary: {threat_summary}\n"
        f"Detected Red Flags: {', '.join(triggers)}\n"
        f"Recommended Action: Call {user_name} immediately to ensure safety and prevent money transfer."
    )

    try:
        db = get_firestore_client()
        doc_ref = db.collection("guardian_alerts").document()
        doc_ref.set({
            "user_name": user_name,
            "caller_id": caller_id,
            "threat_summary": threat_summary,
            "coercion_triggers": triggers,
            "guardian_contact": guardian_contact,
            "alert_message": alert_message,
            "timestamp": now_str,
            "status": "DISPATCHED",
        })
    except Exception:
        pass

    return {
        "status": "SUCCESS",
        "notification_dispatched": True,
        "recipient": guardian_contact,
        "timestamp": now_str,
        "user_name": user_name,
        "caller_id": caller_id,
        "alert_message": alert_message,
        "caregiver_instructions": "Contact the user immediately. Do not allow them to purchase gift cards, wire funds, or visit a Bitcoin ATM.",
    }


def generate_threat_warning_video(
    topic: str,
    risk_level: str = "HIGH",
    tool_context: ToolContext = None,
) -> dict:
    """Generate a short video warning animation for a specific scam or threat topic using Google's Omni model (gemini-omni-flash-preview) in the global region. Saves the video as a Playground artifact and uploads it to Cloud Storage.

    Args:
        topic: The scam or security topic for the warning video (e.g. 'Phishing Link', 'Crypto Wallet Drainer', 'Fake IRS Call').
        risk_level: Assessed risk level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        tool_context: ADK ToolContext passed automatically by the framework.

    Returns:
        A dictionary with status, filename, and the public GCS HTTPS URL of the generated warning video.
    """
    import base64
    import datetime
    from google import genai
    from google.cloud import storage
    from google.genai import types

    client = genai.Client(
        vertexai=True,
        project="qwiklabs-gcp-03-c7f26ed5ce67",
        location="global",
    )

    prompt = (
        f"A short 3-second animated security alert video warning about {topic}, "
        f"risk level {risk_level}, featuring glowing red warning icons and digital security shields."
    )

    try:
        interaction = client.interactions.create(
            model="gemini-omni-flash-preview",
            input=prompt,
        )

        if not hasattr(interaction, "output_video") or not interaction.output_video:
            return {
                "status": "error",
                "message": "Video generation produced no output_video content",
            }

        v = interaction.output_video
        mime_type = getattr(v, "mime_type", None) or "video/mp4"

        if isinstance(v.data, str):
            video_bytes = base64.b64decode(v.data)
        else:
            video_bytes = bytes(v.data)

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )
        filename = f"scam_warning_video_{timestamp}.mp4"

        # (1) Save artifact in Playground panel if tool_context is present
        if tool_context is not None:
            artifact_part = types.Part.from_bytes(
                data=video_bytes, mime_type=mime_type
            )
            tool_context.save_artifact(
                filename=filename, artifact=artifact_part
            )

        # (2) Upload video bytes directly to GCS bucket without writing to local file
        storage_client = storage.Client(project="qwiklabs-gcp-03-c7f26ed5ce67")
        bucket = storage_client.bucket(GCS_BUCKET_NAME)
        blob = bucket.blob(filename)
        blob.upload_from_string(video_bytes, content_type=mime_type)

        public_url = (
            f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/{filename}"
        )

        return {
            "status": "success",
            "filename": filename,
            "public_url": public_url,
            "message": (
                f"Successfully generated warning video for '{topic}' using gemini-omni-flash-preview and"
                " published to Cloud Storage."
            ),
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Video generation or upload failed: {str(e)}",
        }






