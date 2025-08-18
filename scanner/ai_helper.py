import os
import time
import os
import time
import logging
from typing import Dict, List
from openai import OpenAI

class AIHelper:

    def generate_batch(self, prompt: str, model: str = "Qwen/Qwen3-32B:cerebras", base_url: str = "https://router.huggingface.co/v1", max_tokens: int = 1500) -> str:
        """Generate a batch AI response for a list of vulnerabilities using the specified model and base_url."""
        # Create a new OpenAI client if model or base_url differ from defaults
        client = self.client
        if (base_url != self.client.base_url or self.client.api_key != self.api_token):
            client = OpenAI(base_url=base_url, api_key=self.api_token)
        for attempt in range(self.max_retries):
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=0.7
                )
                return response.choices[0].message.content.strip()
            except Exception as e:
                print(f"Batch attempt {attempt + 1} failed: {type(e).__name__}: {e}")
                self.logger.error(f"Batch attempt {attempt + 1} failed: {str(e)}")
                if attempt == self.max_retries - 1:
                    return ""
                time.sleep(self.retry_delay * (attempt + 1))
        return ""
    def __init__(self, api_token: str = None):
        self.api_token = api_token or os.getenv("HF_TOKEN")
        if not self.api_token:
            raise ValueError("HF_TOKEN environment variable not set")
        self.client = OpenAI(
            base_url="https://router.huggingface.co/v1",
            api_key=self.api_token,
        )
        self.logger = logging.getLogger(__name__)
        self.max_retries = 3
        self.retry_delay = 2

    def _call_api(self, prompt: str, max_tokens: int = 300) -> str:
        for attempt in range(self.max_retries):
            try:
                response = self.client.chat.completions.create(
                    model="openai/gpt-oss-20b:novita",
                    messages=[
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    max_tokens=max_tokens,
                    temperature=0.7
                )
                return response.choices[0].message.content.strip()
            except Exception as e:
                print(f"Attempt {attempt + 1} failed: {type(e).__name__}: {e}")
                self.logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt == self.max_retries - 1:
                    return ""
                time.sleep(self.retry_delay * (attempt + 1))
        return ""

    def generate_description(self, vulnerability: Dict) -> str:
        """Generate vulnerability description"""
        current_desc = vulnerability.get("description", "")
        
        try:
            if "outdated" in current_desc.lower():
                prompt = f"Explain security risks of using {vulnerability.get('name')} version " \
                         f"{vulnerability.get('version', 'unknown')}. " \
                         "Focus on technical impact in 2-3 sentences."
            elif "CVE" in vulnerability.get("name", ""):
                prompt = f"Explain {vulnerability.get('name')} in professional terms. " \
                         "Describe attack vectors and technical impact in 2-3 sentences."
            else:
                return current_desc

            response = self._call_api(prompt)
            return response if response else current_desc
        except Exception as e:
            self.logger.error(f"Description generation failed: {str(e)}")
            return current_desc

    def generate_remediation(self, vulnerability: Dict) -> List[str]:
        """Generate prioritized remediation steps with references"""
        current_remediation = vulnerability.get("remediation", [])
        if isinstance(current_remediation, str):
            current_remediation = [current_remediation] if current_remediation else []

        try:
            cvss_score = self._get_cvss_score(vulnerability)
            cvss_text = f"CVSS: {cvss_score:.1f}" if isinstance(cvss_score, float) else "CVSS: N/A"
            
            if "outdated" in str(vulnerability).lower():
                prompt = (
                    f"List 3-5 prioritized steps to upgrade {vulnerability.get('name')} from "
                    f"{vulnerability.get('version')} to {vulnerability.get('latest_version')}. "
                    f"{cvss_text}. Include verification steps and official references. "
                    "Number each step by priority with technical specifics."
                )
            elif "CVE" in vulnerability.get("name", ""):
                prompt = (
                    f"Provide 3-5 mitigation steps for {vulnerability.get('name')} "
                    f"({cvss_text}). Focus on most effective solutions first with "
                    "official references from vendor or CVE details. Number each step "
                    "by priority with technical specifics."
                )
            else:
                return current_remediation

            response = self._call_api(prompt, max_tokens=500)
            if response:
                steps = [step.strip() for step in response.split('\n') 
                        if step.strip() and step[0].isdigit()]
                return steps[:5] if steps else current_remediation
            return current_remediation
        except Exception as e:
            self.logger.error(f"Remediation generation failed: {str(e)}")
            return current_remediation

    def _get_cvss_score(self, vulnerability: Dict) -> float:
        """Enhanced CVSS score extraction with better fallback logic"""
        # Try explicit cvss_score first
        cvss = vulnerability.get('cvss_score')
        if cvss not in [None, 'N/A', '']:
            try:
                return float(cvss)
            except (ValueError, TypeError):
                pass
        
        # Try to extract from description if contains CVSS
        desc = str(vulnerability.get('description', ''))
        if 'CVSS' in desc:
            try:
                parts = desc.split('CVSS')
                score_part = parts[1].split()[0]
                return float(score_part.strip('.:'))
            except (IndexError, ValueError):
                pass
        
        # Fallback to severity mapping
        severity = str(vulnerability.get('severity', '')).lower()
        if 'critical' in severity:
            return 9.0
        elif 'high' in severity:
            return 7.5
        elif 'medium' in severity:
            return 5.0
        elif 'low' in severity:
            return 2.5
        
        return 0.0  # Default if no score can be determined

    def generate_business_impact(self, vulnerability: Dict) -> str:
        """Generate business impact analysis"""
        current_impact = vulnerability.get("business_impact", "")
        cvss_score = vulnerability.get("cvss_score", "N/A")
        
        try:
            prompt = (
                f"Analyze potential business impact for this vulnerability:\n"
                f"Name: {vulnerability.get('name', 'Unknown')}\n"
                f"Type: {'Outdated component' if 'outdated' in str(vulnerability).lower() else 'Security vulnerability'}\n"
                f"CVSS Score: {cvss_score}\n"
                f"Technical Description: {vulnerability.get('description', '')}\n\n"
                "Provide a concise 3-4 sentence analysis covering:\n"
                "- Potential financial impact\n"
                "- Reputation risks\n" 
                "- Compliance implications\n"
                "- Operational disruption risks"
            )
            
            response = self._call_api(prompt, max_tokens=400)
            return response if response else current_impact
        except Exception as e:
            self.logger.error(f"Business impact generation failed: {str(e)}")
            return current_impact