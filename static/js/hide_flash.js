// Function to hide the flash message after a specified time (in milliseconds)
function hideFlashMessage() {
    var flashMessage = document.getElementById("flash-message");
    if (flashMessage) {
        setTimeout(function() {
            flashMessage.style.display = "none";
        }, 5000); // Change 5000 to the desired duration (in milliseconds)
    }
  }
  // Call the function to hide the flash message
  hideFlashMessage();