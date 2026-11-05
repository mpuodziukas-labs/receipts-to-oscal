import os


class AssessmentResults:
    @classmethod
    def oscal_read(cls, path):
        if os.environ.get("FAKE_TRESTLE_FAIL") == "1":
            raise ValueError("fake trestle rejects this document")
        return cls()
