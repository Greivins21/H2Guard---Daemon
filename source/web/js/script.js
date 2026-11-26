const flowSteps = [
  {
    title: 'Client opens HTTP/2 connection',
    description: 'A client begins a secure HTTP/2 session. The connection can carry many parallel streams over one TLS channel.',
    active: 'node-client'
  },
  {
    title: 'Multiple streams are generated',
    description: 'The client opens many concurrent HTTP/2 streams. This multiplexing is normal, but it also creates state for the server to track.',
    active: 'node-http2'
  },
  {
    title: 'Streams are rapidly reset',
    description: 'The attacker sends repeated RST_STREAM frames. Each reset forces the server to clean up stream state and may increase processing cost.',
    active: 'node-http2'
  },
  {
    title: 'Kernel intercepts and evaluates traffic',
    description: 'NFQUEUE routes packets to the user-space daemon; the prototype can inspect behavior and return a verdict without breaking the HTTPS session.',
    active: 'node-server'
  }
];

let currentStep = 0;

const titleElement = document.getElementById('demo-step-title');
const descriptionElement = document.getElementById('demo-step-description');
const prevButton = document.getElementById('prev-step');
const nextButton = document.getElementById('next-step');
const resetButton = document.getElementById('reset-step');
const nodeIds = ['node-client', 'node-http2', 'node-server'];

function setActiveNode(activeId) {
  nodeIds.forEach((id) => {
    const node = document.getElementById(id);
    if (node) {
      node.classList.toggle('active', id === activeId);
    }
  });
}

function renderStep(index) {
  const step = flowSteps[index];
  titleElement.textContent = step.title;
  descriptionElement.textContent = step.description;
  setActiveNode(step.active);
  prevButton.disabled = index === 0;
  nextButton.disabled = index === flowSteps.length - 1;
}

function handleNext() {
  if (currentStep < flowSteps.length - 1) {
    currentStep += 1;
    renderStep(currentStep);
  }
}

function handlePrev() {
  if (currentStep > 0) {
    currentStep -= 1;
    renderStep(currentStep);
  }
}

function handleReset() {
  currentStep = 0;
  renderStep(currentStep);
}

if (titleElement && descriptionElement && prevButton && nextButton && resetButton) {
  prevButton.addEventListener('click', handlePrev);
  nextButton.addEventListener('click', handleNext);
  resetButton.addEventListener('click', handleReset);
  document.addEventListener('DOMContentLoaded', () => renderStep(currentStep));
} else {
  document.addEventListener('DOMContentLoaded', () => renderStep(currentStep));
}
