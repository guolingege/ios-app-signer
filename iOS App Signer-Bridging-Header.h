//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//

#import "NSAttributedStringMarkdownParser.h"
#import <sandbox.h>

// Seatbelt's C API still supports a process-wide, inherited deny policy. Swift marks
// it unavailable; keep the compatibility boundary here and fail closed on error.
static inline int SignerActivateOfflinePolicy(void) {
    char *error = NULL;
    int result = sandbox_init("(version 1) (allow default) (deny network*)", 0, &error);
    if (error != NULL) { sandbox_free_error(error); }
    return result;
}
