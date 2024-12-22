//CIRCLE CHARTS (index)

leftInSpend = leftInSpend;
spendingColor = spendingColor;
const data = {
    labels: ['Expenses'],
    datasets: [{
    label: 'Money Spent', 
    data: [leftInSpend, leftInSpend], 
    backgroundColor: [spendingColor, '#FFFFFF'], 
    }]
  };

  // Configure your chart
  const config = {
    type: 'doughnut',
    data: data,
    options: {
      responsive: true,
      cutout: "65%",
      plugins: {
        legend: {
          position: 'top',
        },
        tooltip: {
          enabled: true,
        }
      }
    },
  };

  // Render the chart on the canvas element
  const ctx = document.getElementById('myChart').getContext('2d');
  const myChart = new Chart(ctx, config);

  
  const data2 = {
    labels: ['categories'],
    datasets: [{
    label: 'Financial Data',
    data: [ 300, 200], 
    backgroundColor: ['#ADD8E6', '#FFFFFF'], 
    }]
  };

  // Configure your chart
  const config2 = {
    type: 'doughnut',
    data: data2,
    options: {
      responsive: true,
      cutout: "65%",
      plugins: {
        legend: {
          position: 'top',
        },
        tooltip: {
          enabled: false,
        }
      },
    },
  };

  // Render the chart on the canvas element
  const ctx2 = document.getElementById('myChart2').getContext('2d');
  const myChart2 = new Chart(ctx2, config2);

function correctDecimals(input) {
  let value = parseFloat(input.value);
  if (!isNaN(value)) {
    input.value = value.toFixed(2);
  }
}

tagNames = tagNames;
  colors = colors;
  counts = counts;

  const data3 = {
    labels: tagNames,
    datasets: [{
    label: 'Expenses',
    data: counts, 
    backgroundColor: colors,
    }]
  };

  // Configure your chart
  const config3 = {
    type: 'doughnut',
    data: data3,
    options: {
      responsive: true,
      cutout: "65%",
      plugins: {
        legend: {
          display: false,
        },
        tooltip: {
          enabled: true,
        }
      }
    },
  };

  // Render the chart on the canvas element
  const ctx3 = document.getElementById('myChart3').getContext('2d');
  const myChart3 = new Chart(ctx3, config3);

console.log(data); 

function scrollToMain() {
  const mainSection = document.querySelector('.main');
  mainSection.scrollIntoView({ behavior: 'smooth' }); // Smooth scrolling to the .main container
}