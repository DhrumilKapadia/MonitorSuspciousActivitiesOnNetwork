import dash
import dash_core_components as dcc
import dash_html_components as html
import pandas as pd
import sqlite3
import plotly.express as px
from dash.dependencies import Input, Output

# Initialize Dash app
app = dash.Dash(__name__)

# Layout of the dashboard
app.layout = html.Div([
    html.H1('Network Traffic Dashboard'),
    dcc.Graph(id='traffic-graph'),
    html.Div(id='alert-div'),
    dcc.Interval(
        id='interval-component',
        interval=5 * 1000,  # Update every 5 seconds
        n_intervals=0
    )
])


def fetch_data():
    conn = sqlite3.connect('network_traffic.db')
    query = "SELECT * FROM packets"
    df = pd.read_sql(query, conn)
    conn.close()
    return df


def fetch_alerts():
    conn = sqlite3.connect('network_traffic.db')
    query = "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 5"
    df = pd.read_sql(query, conn)
    conn.close()
    return df


@app.callback(
    Output('traffic-graph', 'figure'),
    Output('alert-div', 'children'),
    [Input('interval-component', 'n_intervals')]
)
def update_dashboard(n_intervals):
    df = fetch_data()
    alerts_df = fetch_alerts()

    if df.empty:
        fig = px.scatter(title="No Data Available")
    else:
        fig = px.scatter(df, x='timestamp', y='protocol', color='protocol',
                         title='Network Traffic by Protocol')

    # Generate alert messages without IP addresses
    alert_messages = ""
    if not alerts_df.empty:
        alert_messages = "Recent Alerts:\n" + "\n".join(
            [f"{row['timestamp']}: {row['message']}" for _, row in alerts_df.iterrows()]
        )

    return fig, alert_messages


if __name__ == "__main__":
    app.run_server(debug=True)
