# Security Specification — MR. Ahmed Aboo Educational Platform

## 1. Data Invariants
1. Default-deny catch-all blocks all unauthenticated and unmatched reads/writes.
2. Only verified Teacher (`am0502881@gmail.com` with `email_verified == true` or active entry in `/teachers/{uid}`) may read/write global student lists, private notes, payments, groups, schedules, library sources, question bank, audit logs, and `/examAnswerKeys/{examId}`.
3. Students and Parents NEVER read `/examAnswerKeys/{examId}` or `/students/{studentId}/privateNotes/{noteId}` or `/students` list queries.
4. Students and Parents can only read their own linked `/studentPortals/{studentId}` and `/students/{studentId}` via verified `/userLinks/{uid}`.
5. Exam attempts enforce `studentUid == request.auth.uid`, immutable `startedAt == request.time` on create, and terminal state lock once `status == 'graded'`.
6. Portal invites store only SHA-256 hashes of `phone:code` and cannot be listed by non-teachers.

## 2. Dirty Dozen Attack Payloads (Expected: PERMISSION_DENIED)
1. Unauthenticated read on `/students/stu_1`.
2. Student reading `/examAnswerKeys/exam_1`.
3. Student reading `/students/stu_other` (another student's PII).
4. Parent reading `/studentPortals/stu_other` (unlinked child).
5. Student listing `/students` collection.
6. Student creating `/teachers/attacker_uid` with `role: "owner"`.
7. Student updating `/examAttempts/att_1` after `status == "submitted"` to inflate `totalScore`.
8. Student updating `/examAttempts/att_1` with fake `startedAt` timestamp.
9. Student reading `/students/stu_1/privateNotes/note_1`.
10. Parent listing `/payments` collection.
11. Student writing a shadow field `{ isAdmin: true }` into `/userLinks/{uid}`.
12. Unauthenticated user listing `/portalInvites`.
