// Function to add "active" class to the appropriate link
function setActiveLink() {
    const currentLocation = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-link');

    navLinks.forEach(link => {
      const linkUrl = link.getAttribute('href');
      if (currentLocation === linkUrl) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });
  }

  // Call the function to set the active link initially
  setActiveLink();


// JavaScript function to toggle the button color
function toggleCompletion(taskId) {
  const button = document.getElementById('task' + taskId);
  const isCompleted = button.classList.contains('btn-success');

  // Toggle button color and text
  button.classList.toggle('btn-success');
  button.classList.toggle('btn-secondary');
  button.textContent = isCompleted ? 'Not Completed' : 'Completed';

  // Make an AJAX request to update completion status in the database
  fetch(`/toggle_completion/${taskId}`, { method: 'POST' })
      .then(response => response.json())
      .then(data => {
          console.log(data);

          // Move the task card to the appropriate section based on completion status
          const taskCard = button.closest('.card');
          if (isCompleted) {
              document.getElementById('uncompletedTasks').appendChild(taskCard);
          } else {
              document.getElementById('completedTasks').appendChild(taskCard);
          }
      })
      .catch(error => console.error('Error:', error));
}



