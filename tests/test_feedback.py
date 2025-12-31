import unittest
import os
import sys

# Add parent directory to path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, get_db, init_db

class FeedbackTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Use a temporary memory database for isolation if possible, 
        # but app.py hardcodes DB_PATH. 
        # So we will insert test data and clean it up.
        self.db = get_db()

    def tearDown(self):
        # Clean up test data
        self.db.execute("DELETE FROM users WHERE email='test_citizen@example.com'")
        self.db.execute("DELETE FROM complaints WHERE title='Test Feedback Complaint'")
        self.db.commit()
        self.db.close()
        self.app_context.pop()

    def test_feedback_flow(self):
        # 1. Create Citizen
        self.db.execute("INSERT INTO users (name, email, password, role, is_active) VALUES ('Test Citizen', 'test_citizen@example.com', 'hashedpw', 'citizen', 1)")
        self.db.commit()
        user_id = self.db.execute("SELECT id FROM users WHERE email='test_citizen@example.com'").fetchone()[0]

        # 2. Login (Simulate session)
        with self.app.session_transaction() as sess:
            sess['user_id'] = user_id
            sess['role'] = 'citizen'

        # 3. Create Complaint
        self.db.execute("INSERT INTO complaints (title, citizen_id, status) VALUES ('Test Feedback Complaint', ?, 'Pending')", (user_id,))
        self.db.commit()
        complaint_id = self.db.execute("SELECT id FROM complaints WHERE title='Test Feedback Complaint'").fetchone()[0]

        # 4. Try submitting feedback (Should Fail - Not Resolved)
        response = self.app.post('/submit_feedback', data={
            'complaint_id': complaint_id,
            'rating': 5,
            'feedback': 'Premature feedback'
        })
        self.assertEqual(response.status_code, 400)

        # 5. Resolve Complaint
        self.db.execute("UPDATE complaints SET status='Resolved' WHERE id=?", (complaint_id,))
        self.db.commit()

        # 6. Submit Feedback (Should Success)
        response = self.app.post('/submit_feedback', data={
            'complaint_id': complaint_id,
            'rating': 5,
            'feedback': 'Great work!'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # 7. Verify DB
        row = self.db.execute("SELECT rating, feedback FROM complaints WHERE id=?", (complaint_id,)).fetchone()
        self.assertEqual(row['rating'], 5)
        self.assertEqual(row['feedback'], 'Great work!')
        print("Feedback verification successful!")

if __name__ == '__main__':
    unittest.main()
