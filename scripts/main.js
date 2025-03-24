// Create Glowing Orbs Dynamically
const orbsLayer = document.querySelector('.orbs-layer');
for (let i = 0; i < 3; i++) {
  const orb = document.createElement('div');
  orb.classList.add('orb-particle');
  orbsLayer.appendChild(orb);
}

// Dropdown Menu Toggle
const menuToggle = document.getElementById('menu-toggle');
const menuDropdown = document.getElementById('menu-dropdown');

menuToggle.addEventListener('click', () => {
  menuDropdown.classList.toggle('active');
});

// Category Filtering
let currentCategory = 'all';
const categoryButtons = document.querySelectorAll('.category-btn');
const posts = document.querySelectorAll('.post');
const discussions = document.querySelectorAll('.discussion');

categoryButtons.forEach(button => {
  button.addEventListener('click', () => {
    categoryButtons.forEach(btn => btn.classList.remove('active'));
    button.classList.add('active');
    currentCategory = button.getAttribute('data-category');

    // Update visibility based on mode
    updateFeedVisibility();
  });
});

document.querySelector('.category-btn[data-category="all"]').click();

// Feed Mode Toggle
const modeButtons = document.querySelectorAll('.mode-btn');
const feedNews = document.querySelector('.feed-news');
const currentDiscussions = document.querySelector('.current-discussions');
let currentMode = 'feed-news';

modeButtons.forEach(button => {
  button.addEventListener('click', () => {
    modeButtons.forEach(btn => btn.classList.remove('active'));
    button.classList.add('active');
    currentMode = button.getAttribute('data-mode');

    // Update visibility
    updateFeedVisibility();
  });
});

function updateFeedVisibility() {
  if (currentMode === 'feed-news') {
    feedNews.classList.remove('hidden');
    currentDiscussions.classList.add('hidden');

    posts.forEach(post => {
      if (currentCategory === 'all' || post.getAttribute('data-category') === currentCategory) {
        post.classList.add('active');
      } else {
        post.classList.remove('active');
      }
    });
  } else {
    feedNews.classList.add('hidden');
    currentDiscussions.classList.remove('hidden');

    discussions.forEach(discussion => {
      if (currentCategory === 'all' || discussion.getAttribute('data-category') === currentCategory) {
        discussion.classList.add('active');
      } else {
        discussion.classList.remove('active');
      }
    });
  }
}

// Add Post Functionality
const addPostBtn = document.getElementById('add-post-btn');
const addPostForm = document.getElementById('add-post-form');
const submitPostBtn = document.getElementById('submit-post');
const postContent = document.getElementById('post-content');

addPostBtn.addEventListener('click', () => {
  addPostForm.classList.toggle('hidden');
});

submitPostBtn.addEventListener('click', () => {
  if (postContent.value && currentCategory !== 'all') {
    const newPost = document.createElement('div');
    newPost.classList.add('post', 'holo-card', 'active');
    newPost.setAttribute('data-category', currentCategory);
    newPost.innerHTML = `
      <div class="post-header flex items-center space-x-4">
        <img src="assets/images/avatar-placeholder.png" alt="Avatar" class="avatar w-12 h-12 rounded-full">
        <div>
          <span class="username font-semibold text-blue-300">You</span>
          <p class="text-sm text-gray-400">Just now</p>
        </div>
      </div>
      <p class="mt-4 text-lg">${postContent.value} #${currentCategory.replace(/-/g, '')}</p>
      <div class="post-actions flex items-center space-x-4 mt-4">
        <div class="flex items-center space-x-2">
          <img src="assets/images/like-button.png" alt="Like" class="action-btn w-6 h-6 cursor-pointer like-btn">
          <span class="like-count text-sm text-gray-400">0</span>
        </div>
        <div class="flex items-center space-x-2">
          <img src="assets/images/comment-button.png" alt="Comment" class="action-btn w-6 h-6 cursor-pointer comment-btn">
          <span class="comment-count text-sm text-gray-400">0</span>
        </div>
      </div>
      <div class="comments hidden mt-4">
        <div class="flex space-x-3">
          <input type="text" class="comment-input flex-1 p-2 rounded-lg bg-gray-800 text-white border border-gray-600" placeholder="Add a comment...">
          <img src="assets/images/send-comment.png" alt="Send Comment" class="send-comment-btn w-6 h-6 cursor-pointer">
        </div>
        <div class="comment-list mt-4"></div>
      </div>
    `;
    feedNews.insertBefore(newPost, feedNews.firstChild);
    postContent.value = '';
    addPostForm.classList.add('hidden');

    // Rebind event listeners for new post
    bindPostEventListeners(newPost);
  }
});

// Like Functionality
function bindPostEventListeners(post) {
  const likeBtn = post.querySelector('.like-btn');
  const commentBtn = post.querySelector('.comment-btn');
  const sendCommentBtn = post.querySelector('.send-comment-btn');

  likeBtn.addEventListener('click', () => {
    const likeCount = likeBtn.nextElementSibling;
    let count = parseInt(likeCount.textContent);
    likeCount.textContent = count + 1;
  });

  commentBtn.addEventListener('click', () => {
    const commentsSection = commentBtn.parentElement.nextElementSibling;
    commentsSection.classList.toggle('hidden');

    const commentCount = commentBtn.nextElementSibling;
    const commentList = commentsSection.querySelector('.comment-list');
    commentCount.textContent = commentList.children.length;
  });

  sendCommentBtn.addEventListener('click', () => {
    const input = sendCommentBtn.previousElementSibling;
    const commentList = sendCommentBtn.nextElementSibling;
    if (input.value) {
      const comment = document.createElement('p');
      comment.textContent = `You: ${input.value}`;
      commentList.appendChild(comment);
      input.value = '';

      const commentCount = sendCommentBtn.closest('.post').querySelector('.comment-count');
      commentCount.textContent = commentList.children.length;
    }
  });
}

document.querySelectorAll('.post').forEach(post => bindPostEventListeners(post));

// Poll Functionality
const pollButtons = document.querySelectorAll('.poll-btn');
const pollResults = document.querySelector('.poll-results');
let votes = { basketball: 0, football: 0 };

pollButtons.forEach(button => {
  button.addEventListener('click', () => {
    const option = button.getAttribute('data-option');
    votes[option]++;
    document.querySelector('.basketball-votes').textContent = votes.basketball;
    document.querySelector('.football-votes').textContent = votes.football;
    pollResults.classList.remove('hidden');
  });
});

// Holo-Chat Functionality
const chatOrb = document.querySelector('.chat-orb');
const chatContent = document.querySelector('.chat-content');
const closeChatBtn = document.getElementById('close-chat');

chatOrb.addEventListener('click', () => {
  chatContent.classList.toggle('active');
});

closeChatBtn.addEventListener('click', () => {
  chatContent.classList.remove('active');
});

document.querySelector('.send-btn').addEventListener('click', () => {
  const input = document.getElementById('chat-input');
  const messages = document.getElementById('chat-messages');
  if (input.value) {
    const message = document.createElement('p');
    message.textContent = `You: ${input.value}`;
    messages.appendChild(message);
    input.value = '';
    messages.scrollTop = messages.scrollHeight;
  }
});

// Community Pulse Animation
const pulseItems = document.querySelectorAll('.pulse-board li');
pulseItems.forEach((item, index) => {
  setInterval(() => {
    item.style.opacity = '0.5';
    setTimeout(() => {
      item.style.opacity = '1';
    }, 500);
  }, (index + 1) * 2000);
});