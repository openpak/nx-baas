# Archived Ryujinx visit-flow review (2026-10-13)

Owner authorized read-only inspection of the retired OpenPak Ryujinx fork.
No checkout was reactivated, built, installed, or launched. Selected source
files, two pages of commit metadata, and the NPNS change were retrieved through
GitHub into scratch/harbor-acnh-flight-20261013/archived-ryujinx and adjacent
private research files.

Relevant changes found:

- 75ca699cf16d: NPNS subscription calls, receive/state events, token creation,
  destruction and validity, suspend/resume. Avoided an emulator exception at
  online entry. Harbor already implements the subscription/event behavior;
  its CreateToken remains a stub, whereas Ryujinx zero-filled a supplied token
  buffer. No evidence currently connects that difference to the HTTP flight
  error, which happens on /emigrations rather than notification_tokens.
- 78a314fefe93: profanity/dictionary diagnostics. They established that the
  Code-of-Conduct refusal was not coming from the emulator's word filter.
- caeceb919b98: device-save selection for cloud synchronization. This addressed
  2002-1002 on game shutdown, not visits or the departure request.

Reviewed built-in patches, guest SSL implementation, OpenPak DNS/network profile,
server setup and handoffs. No /emigrations rewrite, response fabrication, or
ACNH-specific built-in patch was found in those inspected files. This is a
bounded review, not proof that no historical local/uncommitted modification
existed. The documented successful visits used Switch and Ryujinx; Harbor has
not yet passed this flight flow. The recorded working nx-baas v0.12.57 also
lacks /emigrations. Current request/response contract still needs evidence.

Experimental departure acknowledgement was removed from production after
2219-0021; the preceding account-service unit is restored. Do not infer a
working fix from an HTTP 200 or invent response fields.
