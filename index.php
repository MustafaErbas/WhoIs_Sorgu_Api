<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WHOIS Lookup</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f3f4f6;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
        }

        .container {
            background-color: #fff;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            width: 600px;
            max-width: 90%;
            transition: box-shadow 0.3s;
            margin-top: 20px;
        }

        .container:hover {
            box-shadow: 0 0 30px rgba(0, 0, 0, 0.2);
        }

        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }

        form {
            display: flex;
            flex-direction: column;
            align-items: center;
            width: 100%;
            position: sticky;
            top: 0;
            background-color: #fff;
            z-index: 1000;
            padding-top: 10px;
            padding-bottom: 10px;
        }

        input[type="text"] {
            padding: 14px;
            border: none;
            border-radius: 8px;
            background-color: #f9f9f9;
            margin-bottom: 20px;
            width: 100%;
            box-sizing: border-box;
        }

        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            padding: 14px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.3s, transform 0.3s, box-shadow 0.3s;
            width: 100%;
            box-sizing: border-box;
            position: relative;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        input[type="submit"]:hover {
            background-color: #45a049;
            transform: translateX(5px) scale(1.05);
            box-shadow: 0 6px 8px rgba(0, 0, 0, 0.3);
        }

        input[type="submit"]::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background-color: rgba(255, 255, 255, 0.2);
            transition: left 0.3s;
            z-index: 0;
        }

        input[type="submit"]:hover::before {
            left: 0;
        }

        input[type="submit"] span {
            position: relative;
            z-index: 1;
            transition: color 0.3s;
        }

        input[type="submit"]:hover span {
            color: #fff;
        }

        .result {
            margin-top: 30px;
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            transition: box-shadow 0.3s;
            width: 100%;
            box-sizing: border-box;
        }

        .result:hover {
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.2);
        }

        .result p {
            margin: 0;
            color: #333;
        }

        ul {
            list-style-type: none;
            padding-left: 0;
        }

        li {
            background-color: #f0f0f0;
            border: 1px solid #ddd;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
        }

        li strong {
            color: #333;
        }

        ul ul {
            margin-left: 20px;
            margin-top: 10px;
        }

        ul ul li {
            background-color: #e9e9e9;
            border-color: #ccc;
        }

        ul ul ul {
            margin-left: 20px;
        }

        ul ul ul li {
            background-color: #e0e0e0;
            border-color: #bbb;
        }
    </style>
</head>
<body>
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<div class="container">
    <h1>WHOIS Lookup</h1>
    <form id="whoisForm" method="post">
        <label>
            <input type="text" id="domain" name="domain" placeholder="Enter domain name">
        </label>
        <input type="submit" value="Lookup">
    </form>
    <div id="result"></div>
</div>
<script>
    $(document).ready(function() {
        $('#whoisForm').on('submit', function(e) {
            e.preventDefault();
            let domain = $('#domain').val();
            let domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            if (!domainRegex.test(domain)) {
                $('#result').html('Invalid domain format.');
                return;
            }
            $.ajax({
                url: 'WhoIsInfoApi.php',
                method: 'POST',
                data: { domain: domain },
                success: function(response) {
                    let data = (typeof response === 'string') ? JSON.parse(response) : response;
                    let html = formatData(data);
                    $('#result').html(html);
                },
                error: function(xhr, status, error) {
                    $('#result').html('Error: ' + error);
                }
            });
        });

        function formatData(data) {
            let html = '<ul>';
            for (let key in data) {
                if (data.hasOwnProperty(key)) {
                    html += '<li><strong>' + key + ':</strong> ';
                    if (typeof data[key] === 'object' && !Array.isArray(data[key])) {
                        html += formatData(data[key]);
                    } else if (Array.isArray(data[key])) {
                        html += '<ul>';
                        data[key].forEach(function(item) {
                            html += '<li>' + (typeof item === 'object' ? formatData(item) : item) + '</li>';
                        });
                        html += '</ul>';
                    } else {
                        html += data[key];
                    }
                    html += '</li>';
                }
            }
            html += '</ul>';
            return html;
        }
    });
</script>

</body>
</html>