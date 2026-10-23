# Admins can edit and delete users whose names contain _ or -
source "$(dirname "$0")/../lib.sh"; start admin
sql "INSERT INTO users(username, password, email, is_verified) VALUES('jo_e-x', 'x', 'joe@example.invalid', 1)"
check "admin opens the edit page" "$(status admin profile/edit/jo_e-x)" 200
check "edit form is shown" "$(page admin profile/edit/jo_e-x | grep -c 'action=".*profile/edit/jo_e-x"')" 1
P admin profile/edit/jo_e-x 'email=joe@example.invalid' 'bio=Edited by admin' >/dev/null
check "admin edits the bio" "$(q "SELECT bio FROM users WHERE username = 'jo_e-x'")" 'Edited by admin'
P admin profile/delete/jo_e-x confirm=yes >/dev/null
check "admin deletes the user" "$(q "SELECT COUNT(*) FROM users WHERE username = 'jo_e-x'")" 0
finish
