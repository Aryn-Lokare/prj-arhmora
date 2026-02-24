import unittest
from unittest.mock import MagicMock, patch
from api.scanner.gemini_explainer import GeminiExplainer

class TestAutoFix(unittest.TestCase):

    def setUp(self):
        self.explainer = GeminiExplainer()
        self.explainer.client = MagicMock()  # Mock Gemini client

    def test_fallback_code_fix_python_sqli(self):
        # Test fallback when API key is missing or fails
        tech_stack = {'language': 'python', 'framework': 'django'}
        
        fix = self.explainer._get_fallback_code_fix('SQL Injection', tech_stack)
        
        self.assertEqual(fix['language'], 'python')
        self.assertIn('parameterized queries', fix['explanation'])
        self.assertIn('cursor.execute', fix['code_snippet'])

    def test_fallback_code_fix_php_xss(self):
        tech_stack = {'language': 'php', 'framework': 'laravel'}
        
        fix = self.explainer._get_fallback_code_fix('Reflected XSS', tech_stack)
        
        self.assertEqual(fix['language'], 'php')
        self.assertIn('htmlspecialchars', fix['code_snippet'])
        self.assertIn('Blade', fix['code_snippet'])

    @patch('api.scanner.gemini_explainer.GeminiExplainer._parse_code_fix_response')
    def test_generate_code_fix_api_call(self, mock_parse):
        # Mock API response
        mock_response = MagicMock()
        mock_response.text = '{"code": "print(1)"}'
        self.explainer.client.models.generate_content.return_value = mock_response
        self.explainer.enabled = True  # Enable explainer for this test
        
        mock_parse.return_value = {'code_snippet': 'print(1)'}

        tech_stack = {'language': 'python', 'framework': 'flask'}
        evidence = 'Error at line 1'
        
        self.explainer.generate_code_fix(
            finding_type='Debug Mode Enabled',
            tech_stack=tech_stack,
            evidence=evidence,
            affected_url='http://test.com'
        )

        # Verify API called with prompt containing context
        self.explainer.client.models.generate_content.assert_called_once()
        call_args = self.explainer.client.models.generate_content.call_args
        prompt = call_args[1]['contents']
        
        self.assertIn('python', prompt.lower())
        self.assertIn('flask', prompt.lower())
        self.assertIn('debug mode', prompt.lower())

    def test_parse_code_fix_response_json(self):
        # Test parsing JSON response from Gemini
        valid_json = '''
        {
            "code_snippet": "updated_code()",
            "explanation": "Fixed validation",
            "references": ["http://docs.com"]
        }
        '''
        
        parsed = self.explainer._parse_code_fix_response(valid_json, 'python', 'django')
        
        self.assertEqual(parsed['code_snippet'], "updated_code()")
        self.assertEqual(parsed['explanation'], "Fixed validation")
        self.assertEqual(parsed['references'], ["http://docs.com"])

    def test_parse_code_fix_response_markdown(self):
        # Test parsing Markdown code block response
        markdown_text = '''
        Here is the fix:
        ```python
        def secure():
            pass
        ```
        Explanation: Use secure function.
        '''
        
        parsed = self.explainer._parse_code_fix_response(markdown_text, 'python', 'django')
        
        self.assertIn('def secure():', parsed['code_snippet'])
        self.assertIn('Use secure function', parsed['explanation'])

if __name__ == '__main__':
    unittest.main()
