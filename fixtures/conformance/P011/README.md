# P011 — AI-Decision Subject, Input and Output Verified

A valid Independent whose single subject is a subject.ai-decision/1 record. The
record is delivered with a text prompt, a binary image supplied through the
streaming-digest path, and a text answer. The verifier matches the record against
the certificate's commitment, then recomputes every disclosed part's salted
commitment under the profile and nonce the matched record declares
(verifier-toolkit/1 §8.5.6).
All checks pass. The match says the held materials are the ones the
committed record names; it says nothing about the decision's merit.