import React, { useEffect, useState } from "react";
import { getMetrics, getTimeline } from "../api/api";
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";

const Dashboard = () => {
  const [metrics, setMetrics] = useState({});
  const [timeline, setTimeline] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      const m = await getMetrics();
      const t = await getTimeline();
      setMetrics(m);
      setTimeline(t);
    };
    fetchData();
  }, []);

  return (
    <div>
      <h2>Dashboard</h2>
      <div>
        <p>Toplam Tehdit: {metrics.totalThreats}</p>
        <p>Aktif Olaylar: {metrics.activeIncidents}</p>
        <p>Sistem Uptime: {metrics.systemUptime}%</p>
        <p>Uyumluluk Skoru: {metrics.complianceScore}</p>
      </div>

      <h3>Tehdit Zaman Çizelgesi (Saatlik)</h3>
      <LineChart width={700} height={300} data={timeline}>
        <CartesianGrid stroke="#ccc" />
        <XAxis dataKey="time" />
        <YAxis />
        <Tooltip />
        <Line type="monotone" dataKey="critical" stroke="#d62728" />
        <Line type="monotone" dataKey="high" stroke="#ff7f0e" />
        <Line type="monotone" dataKey="medium" stroke="#2ca02c" />
        <Line type="monotone" dataKey="low" stroke="#1f77b4" />
      </LineChart>
    </div>
  );
};

export default Dashboard;
