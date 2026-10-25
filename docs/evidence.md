# Evidence: nx-baas

## Unknown traffic

Everything unknown is logged in full (`!! UNHANDLED`), which is how the undocumented parts
(friend invitations) get discovered.

## Friends

Adding a friend works end to end on hardware except the console's own friend list, which stays
empty; the whole investigation, every captured shape and every fix, is in
internal research notes.

## The reply the console parses

Two things it has caught, both self-inflicted: an extra top-level `summary` key, and a thumbnail
still saying `/1/default` after the console had uploaded a picture.
