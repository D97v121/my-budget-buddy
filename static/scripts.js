//CIRCLE CHARTS (index)

spend = Math.max(leftInSpend, 0);
spendingColor = spendingColor;
total_spend = total_spend - leftInSpend;
money_lost_this_month = money_lost_this_month;
money_gained_this_month = money_gained_this_month;
save = totalSave;
give = totalGive;
invest = totalInvest;

const data = {
    labels: ['Money left', 'Money spent'],
    datasets: [{
    label: ' ', 
    data: [spend, total_spend], 
    backgroundColor: ['#4BAEA0', '#C76582'], 
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
          display: false,
        },
        tooltip: {
          enabled: true,
        },
        title: {
          display: true,
          text: 'Spend' // This will show "Spend" as a title above the chart
        }
      }
    },
  };

  // Render the chart on the canvas element
  const ctx = document.getElementById('myChart').getContext('2d');
  const myChart = new Chart(ctx, config);

  
  const data2 = {
    labels: ['save', 'spend', 'give' , 'invest'],
    datasets: [{
    label: ' ',
    data: [save, spend, give, invest], 
    backgroundColor: ['#5B9BD5', '#C76582', '#A15C8C', '#7DA2A9'], 
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
          display: false,
        },
        tooltip: {
          enabled: true,
        },
        title: {
          display: true,
          text: 'Money Distribution'
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
    labels: ['lost', 'gained'],
    datasets: [{
    label: ' ',
    data: [money_lost_this_month, money_gained_this_month], 
    backgroundColor: ['#C76582', '#4BAEA0'],  
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
        }, 
        title: {
          display: true,
          text: 'Something here'
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