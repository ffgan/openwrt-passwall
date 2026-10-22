'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require poll';
'require fs';
'require view.passwall.tools as pw';

var ICONS = [
	'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjxzdmcgdmVyc2lvbj0iMS4xIiBpZD0iTGF5ZXJfMSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgeD0iMHB4IiB5PSIwcHgiDQoJIHZpZXdCb3g9IjAgMCA1MTIgNTEyIiBzdHlsZT0iZW5hYmxlLWJhY2tncm91bmQ6bmV3IDAgMCA1MTIgNTEyOyIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSI+DQo8c3R5bGUgdHlwZT0idGV4dC9jc3MiPg0KCS5zdDB7ZmlsbDojMjBiOGQ0O30NCgkuc3Qxe2ZpbGw6I0ZGRkZGRjt9DQoJLnN0MntmaWxsOiNEMkU1RjE7fQ0KCS5zdDN7ZmlsbDojQjVDRkU0O30NCjwvc3R5bGU+DQo8Zz4NCgk8Y2lyY2xlIGNsYXNzPSJzdDAiIGN4PSIyNTYiIGN5PSIyNTYiIHI9IjI1NiIvPg0KCTxwYXRoIGNsYXNzPSJzdDEiIGQ9Ik0zODAuNiwxNDcuM2wtNDUuNywyMzAuNWMwLDAtNi40LDE2LTI0LDguM2wtMTA1LjUtODAuOUwxNjcsMjg2LjdsLTY0LjYtMjEuN2MwLDAtOS45LTMuNS0xMC45LTExLjINCgkJYy0xLTcuNywxMS4yLTExLjgsMTEuMi0xMS44bDI1Ni44LTEwMC43QzM1OS41LDE0MS4yLDM4MC42LDEzMS45LDM4MC42LDE0Ny4zIi8+DQoJPHBhdGggY2xhc3M9InN0MiIgZD0iTTE5Ny4yLDM3NS4yYzAsMC0zLjEtMC4zLTYuOS0xMi40Yy0zLjgtMTIuMi0yMy4zLTc2LjEtMjMuMy03Ni4xbDE1NS4xLTk4LjVjMCwwLDktNS40LDguNiwwDQoJCWMwLDAsMS42LDEtMy4yLDUuNGMtNC44LDQuNS0xMjEuOCwxMDkuNy0xMjEuOCwxMDkuNyIvPg0KCTxwYXRoIGNsYXNzPSJzdDMiIGQ9Ik0yNDUuOCwzMzYuMmwtNDEuNywzOC4xYzAsMC0zLjMsMi41LTYuOCwwLjlsOC03MC43Ii8+DQo8L2c+DQo8L3N2Zz4NCg==',
	'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjwhLS0gR2VuZXJhdG9yOiBBZG9iZSBJbGx1c3RyYXRvciAyMy4wLjEsIFNWRyBFeHBvcnQgUGx1Zy1JbiAuIFNWRyBWZXJzaW9uOiA2LjAwIEJ1aWxkIDApICAtLT4NCjxzdmcgdmVyc2lvbj0iMS4xIiBpZD0i5Zu+5bGCXzEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHg9IjBweCIgeT0iMHB4Ig0KCSB2aWV3Qm94PSIwIDAgMTAwIDEwMCIgc3R5bGU9ImVuYWJsZS1iYWNrZ3JvdW5kOm5ldyAwIDAgMTAwIDEwMDsiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPHN0eWxlIHR5cGU9InRleHQvY3NzIj4NCgkuc3Qwe2ZpbGw6I0ZCQjE0MDt9DQoJLnN0MXtmaWxsOiNGRkZGRkY7fQ0KPC9zdHlsZT4NCjxjaXJjbGUgY2xhc3M9InN0MCIgY3g9IjUwIiBjeT0iNTAiIHI9IjUwIi8+DQo8cGF0aCBjbGFzcz0ic3QxIiBkPSJNODYuOCw0Ny42QzgzLjYsMzMsNzQuOCwyMi41LDY2LjUsMjNoLTAuM2MtMy4zLDAtNi41LDEuMi04LjksMy4zYy0xLjgsMi00LjQsMy4yLTcuMSwzLjINCgljLTIuNiwwLTUuMS0xLjEtNi45LTNjLTIuNS0yLjMtNS44LTMuNS05LjEtMy41aC0wLjRjLTguMi0wLjUtMTcuMSwxMC0yMC4zLDI0LjZjLTMuNSwxNS41LDAuOCwyOS44LDkuNSwzMS45DQoJYzYuMywxLjYsMTMuMy0zLjksMTcuOS0xM2gxOC43YzQuNyw5LjEsMTEuNiwxNC42LDE3LjksMTNDODYsNzcuNCw5MC4yLDYzLjEsODYuOCw0Ny42TDg2LjgsNDcuNnogTTQyLjksNDguNUgzNnY3LjJoLTUuNnYtNy4yDQoJaC02Ljl2LTUuOGg2Ljl2LTcuMkgzNnY3LjJoNi45TDQyLjksNDguNXogTTYyLjcsNDkuMmMtMiwwLjEtMy43LTEuNC0zLjgtMy40Yy0wLjEtMiwxLjQtMy43LDMuNC0zLjhjMi0wLjEsMy43LDEuNCwzLjgsMy40DQoJYzAsMC4xLDAsMC4xLDAsMC4yQzY2LjIsNDcuNSw2NC43LDQ5LjEsNjIuNyw0OS4yQzYyLjcsNDkuMiw2Mi43LDQ5LjIsNjIuNyw0OS4yeiBNNzMuNyw0OS4yYy0yLDAuMS0zLjctMS40LTMuOC0zLjQNCgljLTAuMS0yLDEuNC0zLjcsMy40LTMuOGMyLTAuMSwzLjcsMS40LDMuOCwzLjRjMCwwLjEsMCwwLjEsMCwwLjJjMC4xLDEuOS0xLjQsMy41LTMuMywzLjZINzMuN3oiLz4NCjwvc3ZnPg0K',
	'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAwIDEwMDAiPg0KICA8c3R5bGU+DQogICAgLnN0MXtmaWxsOiNmZmZ9DQogICAgLnN0MntmaWxsOiMwMTk1ZGV9DQogICAgLnN0NHtmaWxsOiNmMmYyZjJ9DQogIDwvc3R5bGU+DQogIDxjbGlwUGF0aCBpZD0iY2xpcENpcmNsZSI+DQogICAgPGNpcmNsZSBjeD0iNTAwIiBjeT0iNTAwIiByPSI0ODAiLz4NCiAgPC9jbGlwUGF0aD4NCiAgPGNpcmNsZSBjeD0iNTAwIiBjeT0iNTAwIiByPSI0ODAiIGZpbGw9IiMwMGEwZWYiLz4NCiAgPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXBDaXJjbGUpIj4NCiAgICA8cGF0aCBkPSJNMTI5LjUgMzQ1aDkwLjljMTkuOCAwIDM1LjYgMiA0Ny40IDRhNzcuNSA3Ny41IDAgMCAxIDM3LjYgMjMuNyAxMzEgMTMxIDAgMCAxIDIzLjcgMzkuNWM1LjkgMTUuOCA3LjkgMzUuNiA3LjkgNTkuMyAwIDE5LjgtMiAzNy42LTcuOSA1My40YTExNC45IDExNC45IDAgMCAxLTI1LjcgNDMuNSA3NyA3NyAwIDAgMS0zNS42IDE5LjhjLTExLjkgNC0yNS43IDUuOS00My41IDUuOWgtOTQuOVYzNDVoLjF6bTUxLjQgNDMuNXYxNjQuMWgzNy42YzEzLjggMCAyMy43IDAgMjkuNy0yIDcuOS0yIDE1LjgtNS45IDE5LjgtOS45IDUuOS00IDkuOS0xMy44IDEzLjgtMjMuNyA0LTExLjkgNS45LTI1LjcgNS45LTQ1LjVzLTItMzMuNi01LjktNDMuNWE2OSA2OSAwIDAgMC0xMy44LTIzLjcgNDUuMyA0NS4zIDAgMCAwLTIzLjctMTEuOWMtNy45LTItMTkuOC0yLTQxLjUtMmgtMjEuN3YtMS45aC0uMnpNMzgwLjYgNTk0LjFWMzQ1SDQzMGwxMDAuOCAxNjYuMVYzNDVoNDcuNHYyNDkuMWgtNDkuNEw0MjggNDMydjE2Mi4xaC00Ny40ek02MTcuOCA1MTMuMWw0OS40LTRjMiAxNS44IDcuOSAyNy43IDE3LjggMzUuNmE1NS4yIDU1LjIgMCAwIDAgMzUuNiAxMS45IDU5IDU5IDAgMCAwIDM1LjYtOS45IDMwLjkgMzAuOSAwIDAgMCAxMS45LTIzLjdjMC01LjktMi05LjktNS45LTE1LjgtNC00LTkuOS03LjktMTcuOC05LjktNS45LTItMTkuOC01LjktMzkuNS05LjlhMTU4LjcgMTU4LjcgMCAwIDEtNTcuMy0yMy43IDYyLjcgNjIuNyAwIDAgMS0yMy43LTQ5LjQgODEgODEgMCAwIDEgOS45LTM1LjYgNjcuNiA2Ny42IDAgMCAxIDMxLjYtMjUuNyAxMjQgMTI0IDAgMCAxIDQ5LjQtNy45YzMxLjYgMCA1NS40IDUuOSA3MS4yIDE5LjhzMjMuNyAzMS42IDI1LjcgNTUuNGwtNDkuNCAyYy0yLTExLjktNS45LTIxLjctMTMuOC0yNy43LTcuOS01LjktMTcuOC03LjktMzEuNi03LjlzLTI1LjcgNC0zMy42IDkuOWMtNS45IDQtNy45IDkuOS03LjkgMTUuOHMyIDExLjkgNy45IDE1LjhjNS45IDUuOSAyMS43IDkuOSA0NS41IDE1LjggMjMuNyA1LjkgNDEuNSAxMS45IDUzLjQgMTcuOHMyMS43IDEzLjggMjcuNyAyNS43YTc4LjEgNzguMSAwIDAgMSA5LjkgMzkuNWMwIDEzLjgtNCAyNy43LTExLjkgMzkuNWE3Ny42IDc3LjYgMCAwIDEtMzMuNiAyNy43IDEzNS42IDEzNS42IDAgMCAxLTUzLjQgOS45Yy0zMS42IDAtNTcuMS01LjktNzMuMi0yMS43LTE4LjItMTcuOS0yNS45LTQxLjctMjkuOS02OS4zeiIgY2xhc3M9InN0MSIvPg0KICAgIDxnPg0KICAgICAgPHBhdGggZD0iTTI0OC4xIDU1MC42YzcuOS0yIDE1LjgtNS45IDE5LjgtOS45IDUuOS00IDkuOS0xMy44IDEzLjgtMjMuNyA0LTExLjkgNS45LTI1LjcgNS45LTQ1LjVzLTItMzMuNi01LjktNDMuNWE2OSA2OSAwIDAgMC0xMy44LTIzLjcgNDUuMyA0NS4zIDAgMCAwLTIzLjctMTEuOWMtNy45LTItMTkuOC0yLTQxLjUtMkgxODF2MTYyLjFoMzcuNmMxMy43LjEgMjMuNi4xIDI5LjUtMS45eiIgY2xhc3M9InN0MiIvPg0KICAgICAgPHBhdGggZD0iTTQ3Ni42IDk0OUg4NzBhNzkuMyA3OS4zIDAgMCAwIDc5LjEtNzkuMVY1MTUuMUw3OTMuMSAzNzJhNzkuNSA3OS41IDAgMCAxIDE4LjUgNDguMWwtNDkuNCAyYy0yLTExLjktNS45LTIxLjctMTMuOC0yNy43LTcuOS01LjktMTcuOC03LjktMzEuNi03LjlzLTI1LjcgNC0zMy42IDkuOWMtNS45IDQtNy45IDkuOS03LjkgMTUuOHMyIDExLjkgNy45IDE1LjhjNS45IDUuOSAyMS43IDkuOSA0NS41IDE1LjhzNDEuNSAxMS45IDUzLjQgMTcuOCAyMS43IDEzLjggMjcuNyAyNS43YTc4LjEgNzguMSAwIDAgMSA5LjkgMzkuNWMwIDEzLjgtNCAyNy43LTExLjkgMzkuNWE3Ny42IDc3LjYgMCAwIDEtMzMuNiAyNy43IDEzNS42IDEzNS42IDAgMCAxLTUzLjQgOS45Yy0zMS42IDAtNTcuMS01LjktNzMuMi0yMS43LTE4LTE3LjgtMjUuNy00MS41LTI5LjctNjkuMmw0OS40LTRjMiAxNS44IDcuOSAyNy43IDE3LjggMzUuNmE1NS4yIDU1LjIgMCAwIDAgMzUuNiAxMS45IDU5IDU5IDAgMCAwIDM1LjYtOS45IDMwLjkgMzAuOSAwIDAgMCAxMS45LTIzLjdjMC01LjktMi05LjktNS45LTE1LjgtNC00LTkuOS03LjktMTcuOC05LjktNS45LTItMTkuOC01LjktMzkuNS05LjlhMTU4LjcgMTU4LjcgMCAwIDEtNTcuMy0yMy43IDYyLjcgNjIuNyAwIDAgMS0xOS4zLTcyLjJsLTQ5LjgtNDUuNnYyNDguNGgtNDkuNEw0MjggNDMydjE2Mi4xaC00Ny40VjQ1Mi4zbC01MS40LTQwLjFjNS45IDE1LjggNy45IDM1LjYgNy45IDU5LjMgMCAxOS44LTIgMzcuNi03LjkgNTMuNGExMTQuOSAxMTQuOSAwIDAgMS0yNS43IDQzLjUgNzcgNzcgMCAwIDEtMzUuNiAxOS44Yy0xMS45IDQtMjUuNyA1LjktNDMuNSA1LjloLTk0Ljl2LTYuOWwtLjQgNi45TDQ3Ni42IDk0OXoiIGNsYXNzPSJzdDIiLz4NCiAgICA8L2c+DQogIDwvZz4NCjwvc3ZnPg0K',
	'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbDpzcGFjZT0icHJlc2VydmUiIGlkPSJMYXllcl8xIiB4PSIwIiB5PSIwIiB2ZXJzaW9uPSIxLjEiIHZpZXdCb3g9IjAgMCA1MTIgNTEyIj48c3R5bGU+LnN0MCwuc3Qxe2ZpbGw6bm9uZTtzdHJva2U6IzI4NGE2YTtzdHJva2Utd2lkdGg6LjI2O3N0cm9rZS1taXRlcmxpbWl0OjEwfS5zdDF7c3Ryb2tlLXdpZHRoOi4xM30uc3Q0e2ZpbGw6IzMzNzhiY30uc3Q1e2ZpbGw6IzE2OWJkNn0uc3Q2e2ZpbGw6IzAwYThkYX08L3N0eWxlPjxwYXRoIGQ9Im0yNTUuOCAxODkuNS01My4yLTYwLjEiIGNsYXNzPSJzdDAiLz48cGF0aCBkPSJtODggMTQzLjMgNDEuNiA2MC44IiBjbGFzcz0ic3QxIi8+PHBhdGggZD0ibTI1NS44IDE4OS42IDUyLjYtNjAuOG0xMSAxMjcuOSA2Mi41LTUyLjZtLTYyLjUgNTIuNSA2Mi41IDU0LjlNMzA5IDM4MWwtNTMuMi01OW0tNTMuMiA1OSA1My4yLTU5bS0xMjYuMS0xMi44IDYwLjEtNTIuNk0xMjkuNyAyMDRsNjAuMSA1Mi42bTY2LTY3LjFMMTI5LjcgMjA0bTEyNi4xLTE0LjVMMzgxLjkgMjA0bS02Mi41IDUyLjYtMTEtMTI3LjhtMTEgMTI3LjhMMzA5IDM4MW03Mi44LTY5LjQtMTI2IDEwLjRtLTEyNi4xLTEyLjhMMjU1LjggMzIybS01My4yIDU5LTEyLjgtMTI0LjNtMTIuOC0xMjcuMy0xMi44IDEyNy4yIiBjbGFzcz0ic3QwIi8+PHBhdGggZD0ibTcxLjkgMjIwLjIgNTcuOC0xNi4ybTEyLjEtMTE4IDYwLjggNDMuNG0xMy45LTcwLjYtMTMuOSA3MC42bTEzLjktNzAuNiA5MS45IDcwbS0xMy45LTcwIDEzLjkgNzBNMzY5LjEgODZsLTYwLjggNDIuOG0xMTUuMiAxNC41LTExNS4xLTE0LjVtNzMuNCA3NS4yIDQxLjYtNjAuOE0zODEuOCAyMDRsNTkgMTYuMm0tNTktMTYuMiA1Ny44IDg3LjlNMjk0LjUgNTguOGwtOTIgNzAuNk0zODEuOCAyMDQgMzY5IDg2bTEyLjggMjI1LjYgNTcuOC0xOS43bS01Ny44IDE5LjcgNTktOTEuNG0tNTkgOTEuNCA0MS42IDU2LjFtLTQxLjYtNTYuMUwzNjkgNDI0LjlNMzA5IDM4MWw2MC4xIDQ0TTMwOSAzODFsMTE0LjUtMTMuM00zMDkgMzgxbC0xMy44IDcxbTEzLjgtNzEtOTIuNSA3MW0tMTMuOS03MSAxMy45IDcxLjJNMjAyLjYgMzgxbDkyLjYgNzFtLTkyLjUtNzEtNjAuOCA0NG02MC44LTQ0TDg4IDM2OC4ybTQxLjctNTktNDEuNyA1OW00MS43LTU5IDEyLjEgMTE1LjdtLTEyLjEtMTE1LjctNTguNC0xNy45bTU4LjQtODcuMy01OC40IDg3LjNtNTguNCAxNy45LTU3LjgtODkuMU0xNDEuOCA4NmwtMTIuMSAxMThNODggMTQzLjNsMTE0LjUtMTMuOSIgY2xhc3M9InN0MSIvPjxwYXRoIGQ9Ik0xNDEuOCA4NiA5Ny4zIDY1LjJNMTQxLjggODZsLTMuNS00OC42bTc4LjIgMjEuNC03OC4xLTIxLjRtNzguMSAyMS40TDE4MyAxNy43bTMzLjUgNDEuMSAxMy45LTQ5LjJNMTQxLjggODZsNDEuMS02OC4ybTExMS42IDQxTDIzMC4zIDkuNm02NC4yIDQ5LjJMMjgwIDcuOW0tNjMuNiA1MC45TDI4MCA3LjltMTQuNSA1MC45TDMyOCAxNy43TTM2OS4xIDg2IDMyOCAxNy44TTM2OS4xIDg2bDQtNDguNm0tNzguNiAyMS40IDc4LjYtMjEuNG0tNCA0OC42IDQ1LjYtMjMuMU0zNjkuMSA4Nmw3OS4yIDEyLjFtLTI0LjggNDUuMiAyNC45LTQ1LjFtLTI0LjkgNDUuMS04LjctODAuNG04LjcgODAuNCA1Mi00bS01MiA0IDcxLjIgNDAuNW0tNTMuOSAzNi40IDM0LjctODFtLTM0LjcgODEgNTMuOC0zNi40bS01My44IDM2LjQgNjAuMSAxMi4xbS02MS4yIDU5LjYgNjEuMy01OS42bS02MS4zIDU5LjYgNjMtMTEuNm0tNjEuOS02MC4xIDYxLjkgNjAuMW0tNjMgMTEuNiA1My44IDM1LjltLTcwIDM5LjggNzAtMzkuOW0tNzAgMzkuOSA1MS41IDUuMm0tMzUuMi04MC45IDM1LjIgODFtLTUxLjQtNS4zIDI0LjMgNDUuNm0tMjQuMy00NS42LTkuMyA3OS44bS0uMS4xLTQ1LjEtMjIuNm0wIDAgMy41IDUwLjRtLTMuNS01MC40IDc4LjYtMTEuNm0tNzguNiAxMS42TDMyOCA0OTQuM00yOTUuMiA0NTJsMzIuOCA0Mi4yTTI5NS4yIDQ1Mmw3Ny41IDIzLjFNMjk1LjIgNDUyIDI4MCA1MDRtMTUuMi01Mi02NC44IDUybS0xMy45LTUyIDEzLjkgNTJtLTEzLjktNTIgNjMuNSA1Mm0tNjMuNS01Mi0zMyA0Mi4ybS00MS43LTY5LjMgNDEuNiA2OS40bTMzLjEtNDIuMy03OC42IDI0LjNtMy45LTUxLjQtNCA1MS41bTQtNTEuNS00NS4xIDI0LjlNODggMzY4LjJsOC43IDgxLjVtNDUuMS0yNC44LTc5LjItMTFNODggMzY4LjJsLTI1LjQgNDUuNk04OCAzNjguMmwtNTIgNS4ybTUyLTUuMi03MS42LTM5LjltNTQuOS0zNy01NC45IDM3bTU0LjktMzctNjIuNS0xMW02Mi41IDExLTM1LjIgODIuMW0zNS44LTE1My4yLTYzIDYwLjFtNjIuNCAxMS02Mi41LTU5bTYzLjEtMTIuMS01My44LTM1LjltNTMuOCAzNS45LTYzIDEyLjFtNjMtMTIuMS0zNS45LTgxbTUyIDQuMS01Mi00bTUyIDQtNjkuOSA0MS4xTTg4IDE0My4zbC0yNC44LTQyLjhNODggMTQzLjNsOS4zLTc4LjFNMTQxLjggODZsLTc4LjcgMTQuNSIgc3R5bGU9ImZpbGw6bm9uZTtzdHJva2UtbWl0ZXJsaW1pdDoxMDtzdHJva2U6IzI0NDA1ZDtzdHJva2Utd2lkdGg6LjEwMSIvPjxwYXRoIGQ9Im0xNTguOSAyODYuNy40LTYwLjggNjAuOC40LS40IDYwLjh6bTY1LjgtNjcgLjQtNjAuOCA2MC44LjQtLjQgNjAuOHptMCAxMzMuNC40LTYwLjggNjAuOC40LS40IDYwLjh6bTY2LjQtNjcgLjQtNjAuOCA2MC44LjQtLjQgNjAuOHoiIHN0eWxlPSJmaWxsOiMyNTZlYTUiLz48cGF0aCBkPSJtMjg3LjYgMTUwIC4zLTQyLjIgNDIuNC4zLS4zIDQyLjJ6bS0xMDYtLjEuMy00Mi4yIDQyLjQuMy0uMyA0Mi4yem0tNzMuNCA3NS4yLjMtNDIuMiA0Mi40LjMtLjMgNDIuMnptMCAxMDYuMS40LTQyLjIgNDIuNC40LS40IDQyLjJ6bTI1Mi44LS44LjMtNDIuMiA0Mi40LjMtLjMgNDIuMnptLjgtMTA1IC40LTQyLjIgNDIuNC40LS40IDQyLjJ6IiBjbGFzcz0ic3Q0Ii8+PHBhdGggZD0ibTczLjkgMTU3IC4yLTI3LjggMjcuNy4yLS4yIDI3Ljh6bTU0LjEtNTYuNS4yLTI3LjggMjcuNy4yLS4yIDI3Ljh6bTc0LjYtMjcuOS4yLTI3LjggMjcuNy4yLS4yIDI3Ljh6TTU3LjUgMjMzLjlsLjItMjcuOCAyNy41LjItLjIgMjcuOHptMzUyLTEwNC4yIDI3LjgtLjIuMiAyNy43LTI3LjguMnptLTU0LjItNTcuNSAyNy44LS4yLjIgMjcuNy0yNy44LjJ6TTI4MC41IDQ1bDI3LjgtLjIuMiAyNy43LTI3LjguMnptMTQ1LjEgMTYxLjUgMjcuOC0uMi4yIDI3LjctMjcuOC4yeiIgY2xhc3M9InN0NSIvPjxwYXRoIGQ9Im0xODEgNDAzLjIuMy00Mi4yIDQyLjQuMy0uMyA0Mi4yem0xMDYgMCAuMy00Mi4yIDQyLjQuMy0uMyA0Mi4yeiIgY2xhc3M9InN0NCIvPjxwYXRoIGQ9Im00MDkuMyAzODEuOC4yLTI3LjggMjcuNy4yLS4yIDI3Ljh6bS01My42IDU3LjEuMi0yNy44IDI3LjcuMi0uMiAyNy44em0tNzQuNSAyNy40LjItMjcuOCAyNy43LjItLjIgMjcuOHpNNDI1LjYgMzA1bC4yLTI3LjggMjcuNy4yLS4yIDI3Ljh6TTczLjkgMzU0LjFsMjcuOC0uMi4yIDI3LjctMjcuOC4yem01NC4yIDU2LjggMjcuOC0uMi4yIDI3LjctMjcuOC4yem03NC4yIDI3LjMgMjcuOC0uMi4yIDI3LjctMjcuOC4yek01Ny44IDI3Ny4zbDI3LjgtLjIuMiAyNy43LTI3LjkuMnoiIGNsYXNzPSJzdDUiLz48cGF0aCBpZD0iQiIgZD0ibTQ2Ny41IDE0Ni43LjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMDk3NTAxNDU3OTIwNjU5ODgxODMwMDAwMDA3NjEzMTYxNTYxNTEzNTY2MzYyXyIgZD0ibTQ4Ny4zIDE5Mi4xLjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMDcxNTQ3MDE0MjgxMTIxMjM3MjkwMDAwMDAyNTQ1NTE0OTE5OTQ4MTQ1MDQ5XyIgZD0ibTQ0MC44IDEwNi41LjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMTA4MzA5MDk5OTkzMzgzODY5NjIwMDAwMDE0ODM0ODY1MjcxMTQ3MjM3NTM1XyIgZD0ibTg5LjYgNzIuMS4xLTE1IDE1LjMuMS0uMSAxNXoiIGNsYXNzPSJzdDYiLz48cGF0aCBpZD0iQl8wMDAwMDAzNjI1Mzc5MjMyMzcyNDE2MTA1MDAwMDAxNzAyNTY0ODkyMjkzNDEwODAzM18iIGQ9Im0xLjYgMjM5LjguMS0xNSAxNS4zLjEtLjEgMTV6IiBjbGFzcz0ic3Q2Ii8+PHBhdGggaWQ9IkJfMDAwMDAwMDMwNzk5MDk4MzcyNDk0NDE0MTAwMDAwMTE3Mzk2NjUxOTA5OTMwNDk0OTJfIiBkPSJtNDA3IDcyLjEuMS0xNSAxNS4zLjEtLjEgMTV6IiBjbGFzcz0ic3Q2Ii8+PHBhdGggaWQ9IkJfMDAwMDAwMjYxMjQ4NDQ4MjY5MzEwNjMxMDAwMDAwMTA0NDAzNTQ4NzMxNTY5NDk5MDlfIiBkPSJtMTAuNCAxOTIuMS4xLTE1IDE1LjMuMS0uMSAxNXoiIGNsYXNzPSJzdDYiLz48cGF0aCBpZD0iQl8wMDAwMDE3MDk4NDg2MzI1OTY2MDU4Mjg4MDAwMDAxNzU0Mjg2NjAyNDM5Njg5MDc4MV8iIGQ9Im0xNzUuOCAyNS41LjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMDQ3MDM4ODU1NTI5Mzg4NDIyMzgwMDAwMDE2OTE3MDM0MDcwNzM1ODY0OTk5XyIgZD0ibTI5IDE0Ni42LjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMTUyOTcyMTc0ODg2NTA2MDM5NzgwMDAwMDA1NDc3ODg4NDM5NTQ2NTA4NDQyXyIgZD0ibTU2LjQgMTA1LjkuMS0xNSAxNS4zLjEtLjEgMTV6IiBjbGFzcz0ic3Q2Ii8+PHBhdGggZD0ibTEzMC42IDI5LjggMTUtLjEuMSAxNS4zLTE1IC4xek0yMjMuNS4zbDE1LS4xLjEgMTUuMy0xNSAuMXoiIGNsYXNzPSJzdDYiLz48cGF0aCBpZD0iQl8wMDAwMDA1NzEzNjY4NzEwOTI5NTIxOTY3MDAwMDAxNTM5MTgxMzc1MjM0MTU0MDczOV8iIGQ9Im0zNjYuMiA0NS4zLjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMDUyMDY1MjM5Mzg5ODIxNjk0MDYwMDAwMDE4MzI3NDczMzAwNDMyNjk5MDM5XyIgZD0ibTQ5NC45IDIzOS4yLjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGQ9Im0yNzIuNCAxNSAuMS0xNSAxNS4zLjEtLjEgMTV6IiBjbGFzcz0ic3Q2Ii8+PHBhdGggaWQ9IkJfMDAwMDAxMDMyNDI5NjA5ODY2ODQ0MTE1NDAwMDAwMTQ1MjE4Nzc5OTAxNzcxMjYzMDZfIiBkPSJtMzIwLjIgMjQuOS4xLTE1IDE1LjMuMS0uMSAxNXoiIGNsYXNzPSJzdDYiLz48cGF0aCBpZD0iQl8wMDAwMDEwNjgzMDIxMDc1ODI1OTU0OTEwMDAwMDAxMjI3MTQ5MTU3NTg5MjYyNjMyMl8iIGQ9Im00MDcgNDU1LjMuMS0xNSAxNS4zLjEtLjEgMTV6IiBjbGFzcz0ic3Q2Ii8+PHBhdGggaWQ9IkJfMDAwMDAwMTY3NTYwNDk1Njg4MzY5MjYxNjAwMDAwMDQ1OTM1NjgyNzkzNDMwMTk5MTFfIiBkPSJtNDk0LjkgMjg3LjYuMS0xNSAxNS4zLjEtLjEgMTV6IiBjbGFzcz0ic3Q2Ii8+PHBhdGggaWQ9IkJfMDAwMDAxMzQ5Mjg1OTQyMTQ5NTUxMTI2NDAwMDAwMDE3MzUwNTQ0MjI0NDg0ODk2NDRfIiBkPSJtODkuNiA0NTUuMy4xLTE1IDE1LjMuMS0uMSAxNXoiIGNsYXNzPSJzdDYiLz48cGF0aCBpZD0iQl8wMDAwMDA2NDM0MTkyMjU0MDg5MTg0NjA1MDAwMDAwMjc1OTc4MDI0NTQyNDg2MTU5M18iIGQ9Im00ODcuMyAzMzYgLjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMTE0NzU2NTU3MDc2NjI3ODE1MjYwMDAwMDEyMTM5NjgwNDczOTQ2NjM0MTM1XyIgZD0ibTMyMC4yIDUwMi41LjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMDg4ODUyMzAwNTIwNDE4NTUwMDUwMDAwMDEyOTgxMzQ5NDA1MDcwODU3Mzc0XyIgZD0ibTQ2Ny41IDM4MS4zLjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMTA3NTY1Nzk2NTYwNTg1MjUwOTcwMDAwMDAwNzcxNjQ0MTc4MDgwNzc5NjY4XyIgZD0ibTQ0MC44IDQyMi4xLjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGQ9Im0zNjUuNiA0NjguMyAxNS0uMS4xIDE1LjMtMTUgLjF6bS05Mi4zIDI4LjQgMTUtLjEuMSAxNS4zLTE1IC4xeiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMDQ2MzAyMDAxNDA5MTQ5NzMwMDMwMDAwMDAxMDU4MzYzODkxODg1ODM1MTc0XyIgZD0ibTEzMC45IDQ4My44LjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMDA3MzkxNjk1Mjk0MDg0NTExNDMwMDAwMDAxNTg1MTc2Njg0MTA2MjQwOTMwXyIgZD0ibTI4LjQgMzgwLjguMS0xNSAxNS4zLjEtLjEgMTV6IiBjbGFzcz0ic3Q2Ii8+PHBhdGggaWQ9IkJfMDAwMDAxMDY4Njc2MzQxMzk5MDAwMjUzMTAwMDAwMTA3MjgzMjg3ODE3NDYyNjQyNDFfIiBkPSJtMTAuNCAzMzUuOS4xLTE1IDE1LjMuMS0uMSAxNXoiIGNsYXNzPSJzdDYiLz48cGF0aCBpZD0iQl8wMDAwMDE2MDE1MTE2MTQ5NzAyNDA2MTc5MDAwMDAwOTk1MzE2NjU0NzgwNjI5Mjg3N18iIGQ9Im01NS44IDQyMi4xLjEtMTUgMTUuMy4xLS4xIDE1eiIgY2xhc3M9InN0NiIvPjxwYXRoIGlkPSJCXzAwMDAwMDU4NTYyMjM4NzExMTkwNDk1NDkwMDAwMDA2NDgxNTA4MTUzNDk2NzQ3OTQ2XyIgZD0ibTEuNiAyODcuNi4xLTE1IDE1LjMuMS0uMSAxNXoiIGNsYXNzPSJzdDYiLz48cGF0aCBpZD0iQl8wMDAwMDAyMjUyMDYxNTA4MDg4Njc1Mjc3MDAwMDAxMjAxODk5NzA3NDMwMzE1NDU4MF8iIGQ9Im0yMjQuMSA1MTEuOC4xLTE1IDE1LjMuMS0uMSAxNXoiIGNsYXNzPSJzdDYiLz48cGF0aCBpZD0iQl8wMDAwMDExMjYxMzMzMDc0OTExMjg5MTU0MDAwMDAwOTg4NTk0NDc2OTYxODA1MzU2MV8iIGQ9Im0xNzUuMiA1MDEuOS4xLTE1IDE1LjMuMS0uMSAxNXoiIGNsYXNzPSJzdDYiLz48L3N2Zz4=',
	'data:image/svg+xml;base64,PHN2ZyB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiBoZWlnaHQ9IjQwMCIgd2lkdGg9IjQwMCIgdmVyc2lvbj0iMS4xIiB2aWV3Qm94PSIwIDAgMTY1MyAxNjUzIiBjbGFzcz0iaWNvbiIgcHJlc2VydmVBc3BlY3RSYXRpbz0ieE1pZFlNaWQgbWVldCI+Cgk8cmVjdCB3aWR0aD0iMTY1MyIgaGVpZ2h0PSIxNjUzIiBmaWxsPSJ0cmFuc3BhcmVudCIvPgoJPGcgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMCwgMzE0LjUpIj4KCQk8cGF0aCBmaWxsPSIjRjc2RTA1IiBkPSJNMjk1LjYzMzQ4OCA3ODMuNjMyODE3YTc0Ljg5ODIxNiA3NC44OTgyMTYgMCAwIDEtNTkuNzIwNjA0LTcyLjU4ODU4di0zOTkuMjM3MTg4YTc3LjUzNzgwMSA3Ny41Mzc4MDEgMCAwIDEgNTkuNzIwNjA0LTcyLjU4ODU4bDM3MC42OTY2NzktODAuMzQyMzYgMzguOTMzODc0LTE1OC44NzAwMDVIMjc0Ljg0Njc1OUEyNzIuODY3MDcgMjcyLjg2NzA3IDAgMCAwIDAuMTY0OTc0IDI3Mi44NzMxNzR2NDcxLjgyNTc2OGEyNzYuNjYxNDczIDI3Ni42NjE0NzMgMCAwIDAgMjc0LjY4MTc4NSAyNzQuODQ2NzU5aDQzMC40MTcyODJsLTM4LjkzMzg3NC0xNTguMjEwMTA5ek0xMzc0LjIzMzc5MyAwLjAwNjEwNEg5NDAuNTE3MDI5bDM5LjU5Mzc3MSAxNTguODcwMDA1IDM3MC42OTY2NzkgODAuMzQyMzZhNzUuMDYzMTkgNzUuMDYzMTkgMCAwIDEgNTkuNzIwNjA0IDcyLjU4ODU4djM5OS4yMzcxODhhNzcuODY3NzQ5IDc3Ljg2Nzc0OSAwIDAgMS01OS43MjA2MDQgNzIuNTg4NThsLTM3MC42OTY2NzkgODAuMzQyMzYtMzkuNTkzNzcxIDE1OC44NzAwMDVIMTM3NC4yMzM3OTNhMjc1LjAxMTczMyAyNzUuMDExNzMzIDAgMCAwIDI3NS42NzE2MjktMjc1LjUwNjY1NVYyNzIuODczMTc0QTI3Ni4xNjY1NTEgMjc2LjE2NjU1MSAwIDAgMCAxMzc0LjIzMzc5MyAwLjAwNjEwNHoiLz4KCQk8cGF0aCBmaWxsPSIjRjc2RTA1IiBkPSJNNjY2LjMzMDE2NyA0OTAuNjM4OTEzaDMxNi4yNTUyNDR2MzguOTMzODc1SDY2Ni4zMzAxNjd6Ii8+Cgk8L2c+Cjwvc3ZnPg==',
	'data:image/svg+xml;base64,PHN2ZyBoZWlnaHQ9IjFlbSIgc3R5bGU9ImZsZXg6bm9uZTtsaW5lLWhlaWdodDoxIiB2aWV3Qm94PSIwIDAgMjQgMjQiIHdpZHRoPSIxZW0iIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHRpdGxlPkdvb2dsZTwvdGl0bGU+PHBhdGggZD0iTTIzIDEyLjI0NWMwLS45MDUtLjA3NS0xLjU2NS0uMjM2LTIuMjVoLTEwLjU0djQuMDgzaDYuMTg2Yy0uMTI0IDEuMDE0LS43OTcgMi41NDItMi4yOTQgMy41NjlsLS4wMjEuMTM2IDMuMzMyIDIuNTMuMjMuMDIyQzIxLjc3OSAxOC40MTcgMjMgMTUuNTkzIDIzIDEyLjI0NXoiIGZpbGw9IiM0Mjg1RjQiPjwvcGF0aD48cGF0aCBkPSJNMTIuMjI1IDIzYzMuMDMgMCA1LjU3NC0uOTc4IDcuNDMzLTIuNjY1bC0zLjU0Mi0yLjY4OGMtLjk0OC42NDgtMi4yMiAxLjEtMy44OTEgMS4xYTYuNzQ1IDYuNzQ1IDAgMDEtNi4zODYtNC41NzJsLS4xMzIuMDExLTMuNDY1IDIuNjI4LS4wNDUuMTI0QzQuMDQzIDIwLjUzMSA3LjgzNSAyMyAxMi4yMjUgMjN6IiBmaWxsPSIjMzRBODUzIj48L3BhdGg+PHBhdGggZD0iTTUuODQgMTQuMTc1QTYuNjUgNi42NSAwIDAxNS40NjMgMTJjMC0uNzU4LjEzOC0xLjQ5MS4zNjEtMi4xNzVsLS4wMDYtLjE0Ny0zLjUwOC0yLjY3LS4xMTUuMDU0QTEwLjgzMSAxMC44MzEgMCAwMDEgMTJjMCAxLjc3Mi40MzYgMy40NDcgMS4xOTcgNC45MzhsMy42NDItMi43NjN6IiBmaWxsPSIjRkJCQzA1Ij48L3BhdGg+PHBhdGggZD0iTTEyLjIyNSA1LjI1M2MyLjEwOCAwIDMuNTI5Ljg5MiA0LjM0IDEuNjM4bDMuMTY3LTMuMDMxQzE3Ljc4NyAyLjA4OCAxNS4yNTUgMSAxMi4yMjUgMSA3LjgzNCAxIDQuMDQzIDMuNDY5IDIuMTk3IDcuMDYybDMuNjMgMi43NjNhNi43NyA2Ljc3IDAgMDE2LjM5OC00LjU3MnoiIGZpbGw9IiNFQjQzMzUiPjwvcGF0aD48L3N2Zz4=',
	'data:image/svg+xml;base64,PHN2ZyBoZWlnaHQ9IjI1MDAiIHZpZXdCb3g9IjAgLTMuMSAyNDkwLjMgMjQ5MyIgd2lkdGg9IjI0OTQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGVsbGlwc2UgY3g9IjEyNDUuMiIgY3k9IjEyNDMuNCIgZmlsbD0iI2ZmZiIgcng9IjEyMTcuNiIgcnk9IjEyNDYuNSIvPjxwYXRoIGQ9Im0xMjQ1LjIgMS42Yy02ODcuNiAwLTEyNDUuMiA1NTcuNC0xMjQ1LjIgMTI0NS4xIDAgNTUwLjIgMzU2LjggMTAxNi45IDg1MS41IDExODEuNSA2Mi4yIDExLjUgODUuMS0yNyA4NS4xLTU5LjkgMC0yOS43LTEuMi0xMjcuOC0xLjctMjMxLjgtMzQ2LjQgNzUuMy00MTkuNS0xNDYuOS00MTkuNS0xNDYuOS01Ni42LTE0My45LTEzOC4zLTE4Mi4yLTEzOC4zLTE4Mi4yLTExMy03Ny4zIDguNS03NS43IDguNS03NS43IDEyNSA4LjggMTkwLjkgMTI4LjMgMTkwLjkgMTI4LjMgMTExLjEgMTkwLjQgMjkxLjMgMTM1LjMgMzYyLjMgMTAzLjUgMTEuMi04MC41IDQzLjQtMTM1LjQgNzkuMS0xNjYuNS0yNzYuNi0zMS41LTU2Ny4zLTEzOC4zLTU2Ny4zLTYxNS40IDAtMTM1LjkgNDguNi0yNDcgMTI4LjMtMzM0LjItMTIuOS0zMS4zLTU1LjUtMTU3LjkgMTIuMS0zMjkuNCAwIDAgMTA0LjYtMzMuNSAzNDIuNSAxMjcuNiA5OS4zLTI3LjYgMjA1LjgtNDEuNCAzMTEuNy00MS45IDEwNS44LjUgMjEyLjQgMTQuMyAzMTEuOSA0MS45IDIzNy43LTE2MS4xIDM0Mi4xLTEyNy42IDM0Mi4xLTEyNy42IDY3LjggMTcxLjUgMjUuMSAyOTguMiAxMi4yIDMyOS41IDc5LjggODcuMiAxMjguMSAxOTguMyAxMjguMSAzMzQuMiAwIDQ3OC4yLTI5MS4zIDU4My42LTU2OC42IDYxNC40IDQ0LjcgMzguNiA4NC41IDExNC40IDg0LjUgMjMwLjYgMCAxNjYuNi0xLjQgMzAwLjctMS40IDM0MS43IDAgMzMuMSAyMi40IDcyIDg1LjUgNTkuNyA0OTQuNS0xNjQuOCA4NTAuOC02MzEuNCA4NTAuOC0xMTgxLjQgMC02ODcuNy01NTcuNS0xMjQ1LjEtMTI0NS4xLTEyNDUuMSIgZmlsbD0iIzVjNmJjMCIvPjwvc3ZnPg==',
	'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjxzdmcKICAgeG1sOnNwYWNlPSJwcmVzZXJ2ZSIKICAgd2lkdGg9IjMwMCIKICAgaGVpZ2h0PSIzMDAiCiAgIHZlcnNpb249IjEuMSIKICAgaWQ9InN2ZzYiCiAgIHNvZGlwb2RpOmRvY25hbWU9IllvdVR1YmVfc29jaWFsX3JlZF9jaXJjbGVfKDIwMjQpLnN2ZyIKICAgaW5rc2NhcGU6dmVyc2lvbj0iMS4yLjIgKGIwYTg0ODY1NDEsIDIwMjItMTItMDEpIgogICB4bWxuczppbmtzY2FwZT0iaHR0cDovL3d3dy5pbmtzY2FwZS5vcmcvbmFtZXNwYWNlcy9pbmtzY2FwZSIKICAgeG1sbnM6c29kaXBvZGk9Imh0dHA6Ly9zb2RpcG9kaS5zb3VyY2Vmb3JnZS5uZXQvRFREL3NvZGlwb2RpLTAuZHRkIgogICB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciCiAgIHhtbG5zOnN2Zz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxkZWZzCiAgIGlkPSJkZWZzMTAiIC8+PHNvZGlwb2RpOm5hbWVkdmlldwogICBpZD0ibmFtZWR2aWV3OCIKICAgcGFnZWNvbG9yPSIjZmZmZmZmIgogICBib3JkZXJjb2xvcj0iIzAwMDAwMCIKICAgYm9yZGVyb3BhY2l0eT0iMC4yNSIKICAgaW5rc2NhcGU6c2hvd3BhZ2VzaGFkb3c9IjIiCiAgIGlua3NjYXBlOnBhZ2VvcGFjaXR5PSIwLjAiCiAgIGlua3NjYXBlOnBhZ2VjaGVja2VyYm9hcmQ9IjAiCiAgIGlua3NjYXBlOmRlc2tjb2xvcj0iI2QxZDFkMSIKICAgc2hvd2dyaWQ9ImZhbHNlIgogICBpbmtzY2FwZTp6b29tPSIxLjI1IgogICBpbmtzY2FwZTpjeD0iMTQyLjQiCiAgIGlua3NjYXBlOmN5PSIxNTAuOCIKICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIxMTg3IgogICBpbmtzY2FwZTp3aW5kb3ctaGVpZ2h0PSI1ODIiCiAgIGlua3NjYXBlOndpbmRvdy14PSIwIgogICBpbmtzY2FwZTp3aW5kb3cteT0iMCIKICAgaW5rc2NhcGU6d2luZG93LW1heGltaXplZD0iMSIKICAgaW5rc2NhcGU6Y3VycmVudC1sYXllcj0ic3ZnNiIgLz4KICA8cmVjdAogICB3aWR0aD0iMzAwIgogICBoZWlnaHQ9IjMwMCIKICAgZmlsbD0iI2ZmZiIKICAgcnk9IjE1MCIKICAgaWQ9InJlY3QyIgogICBzdHlsZT0iZmlsbDojZmYwMDMzO2ZpbGwtb3BhY2l0eToxIiAvPgogIDxwYXRoCiAgIGZpbGw9InJlZCIKICAgZD0iTTE0OS45Mzc1MDU4NyA3OS4yMjI2NzM2NHMtNjMuMjE4ODUuMDAwMDU5LTc5LjA4NTkzOTI2IDQuMTIzMDQ3MDdjLTguNDk1Nzg3MTQgMi4zNzM4MDIwNC0xNS40OTE0MDgyNSA5LjM2OTUwMDE1LTE3Ljg2NTIzNDI5IDE3Ljk5MDIzNzI5LTQuMTIyOTUzMDYgMTUuODY3MTAwMjUtNC4xMjMwNDcwNiA0OC43MjY1NjA3OC00LjEyMzA0NzA2IDQ4LjcyNjU2MDc4cy4wMDAwOTQgMzIuOTg0MjAwNTIgNC4xMjMwNDcwNiA0OC42MDE1NjA3N2MyLjM3MzgyNjA0IDguNjIwNjIwMTQgOS4yNDQ1MDYxNSAxNS40OTEzODAyNSAxNy44NjUyMzQyOSAxNy44NjUyNDAyOSAxNS45OTIwMzAyNSA0LjI0Nzg4MDA3IDc5LjA4NTkzOTI2IDQuMjQ4MDQwMDcgNzkuMDg1OTM5MjYgNC4yNDgwNDAwN3M2My4zNDQxODEwMS0uMDAwMDUgNzkuMjEwOTQxMjctNC4xMjMwNDAwN2M4LjYyMDc5MDE0LTIuMzczODEwMDQgMTUuNDkxMzMwMjUtOS4xMTk2NjAxNSAxNy43NDAyMzAyOC0xNy44NjUyNDAyOSA0LjI0NzkzMDA3LTE1Ljc0MjMyMDI1IDQuMjQ4MDUwMDctNDguNjAxNTYwNzcgNC4yNDgwNTAwNy00OC42MDE1NjA3N3MuMTI0ODQtMzIuOTg0NDYwNTMtNC4yNDgwNTAwNy00OC44NTE1NjA3OGMtMi4yNDg5MDAwMy04LjYyMDczNzE0LTkuMTE5NDQwMTQtMTUuNDkxMzM0MjUtMTcuNzQwMjMwMjgtMTcuNzQwMjM3MjktMTUuODY2NzYwMjYtNC4zNzI4NDcwNy03OS4yMTA5NDEyNy00LjM3MzA0NzA3LTc5LjIxMDk0MTI3LTQuMzczMDQ3MDd6bS0yMC4xMTUyMzAzMiA0MC40ODA0NjQ2NSA1Mi41OTk2MTA4NCAzMC4zNTkzODA0OS01Mi41OTk2MTA4NCAzMC4yMzQzODA0OHYtNjAuNTkzNzYwOTd6IgogICBpZD0icGF0aDQiCiAgIHN0eWxlPSJmaWxsOiNmZmZmZmY7ZmlsbC1vcGFjaXR5OjEiIC8+Cjwvc3ZnPg=='
];

var TMP = '/tmp/etc/passwall';
var LOG_GLOBAL = TMP + '/acl/default/global.log';
var LOG_CHINA = TMP + '/acl/default/chinadns_ng.log';
var LOG_SMART = TMP + '/acl/default/smartdns.log';
var CACHE_VAR = TMP + '/var';

function present(v) {
	return !(v == null || v === false || v === '' || v === 0);
}

function tf(fmt, arg) {
	return _(fmt).replace('%s', arg);
}

function nodeIdOf(n) {
	if (!n)
		return '';
	return n.id || n['.name'] || '';
}

function groupName(v) {
	return (v && v.group && v.group !== '') ? v.group : _('default');
}

function isIPv4(v) {
	var m = String(v || '').match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
	if (!m)
		return false;
	for (var i = 1; i <= 4; i++) {
		var n = +m[i];
		if (m[i] !== String(n) || n > 255)
			return false;
	}
	return true;
}

function isIPv6(v) {
	v = String(v || '');
	if (v.indexOf(':') < 0)
		return false;
	return /^[0-9A-Fa-f:]+$/.test(v);
}

function isIpMask4(v) {
	var p = String(v || '').split('/');
	if (!isIPv4(p[0]))
		return false;
	if (p.length === 1)
		return true;
	if (p.length !== 2)
		return false;
	var n = +p[1];
	return p[1] !== '' && String(n) === p[1] && n >= 0 && n <= 32;
}

function isIpMask6(v) {
	var p = String(v || '').split('/');
	if (!isIPv6(p[0]))
		return false;
	if (p.length === 1)
		return true;
	if (p.length !== 2)
		return false;
	var n = +p[1];
	return p[1] !== '' && String(n) === p[1] && n >= 0 && n <= 128;
}

function isIpAddrPort(v) {
	var s = String(v || '');
	var idx = s.lastIndexOf(':');
	if (idx <= 0)
		return false;
	var host = s.substring(0, idx);
	var port = s.substring(idx + 1);
	if (!/^\d+$/.test(port))
		return false;
	var p = +port;
	if (p < 0 || p > 65535)
		return false;
	if (host.charAt(0) === '[' && host.charAt(host.length - 1) === ']')
		host = host.substring(1, host.length - 1);
	return isIPv4(host) || isIPv6(host);
}

function asText(v) {
	if (typeof v === 'string')
		return v;
	if (v == null)
		return '';
	try {
		return JSON.stringify(v, null, 2);
	}
	catch (e) {
		return String(v);
	}
}

function openLog(getter) {
	return getter.then(function(text) {
		var body = asText(text);
		var w = window.open('', '_blank');
		if (!w) {
			ui.showModal(_('Log'), [
				E('pre', { 'style': 'white-space:pre-wrap;max-height:70vh;overflow:auto' }, body),
				E('div', { 'class': 'right' }, [
					E('button', { 'class': 'btn', 'click': ui.hideModal }, _('CLOSE WIN'))
				])
			]);
			return;
		}
		var pre = w.document.createElement('pre');
		pre.style.whiteSpace = 'pre-wrap';
		pre.textContent = body;
		w.document.body.appendChild(pre);
	});
}

function ul(lines) {
	return E('ul', {}, lines.map(function(line) {
		return E('li', {}, line);
	}));
}

function baseDnsLines() {
	return [
		_('When not matching any domain name list:'),
		_('Remote DNS: Can avoid more DNS leaks, but some domestic domain names maybe to proxy!'),
		_('Direct DNS: Internet experience may be better, but DNS will be leaked!')
	];
}

function smartDnsLines() {
	return baseDnsLines().concat([
		_('Smart: Forward to both direct and remote DNS, if the direct DNS resolution result is a mainland China IP, then use the direct result, otherwise use the remote result.'),
		_('In smart mode, no-ip reply from Direct DNS:'),
		_('Do not accept: Wait and use Remote DNS Reply.'),
		_('Accept: Trust the Reply, using this option can improve DNS resolution speeds for some mainland IPv4-only sites.')
	]);
}

function pageStyle() {
	return E('style', {}, [
		'.pure-g{display:flex;flex-wrap:wrap;}',
		'.pure-u-1-4{width:25%;box-sizing:border-box;}',
		'.pure-u-1-3{width:33.3333%;box-sizing:border-box;}',
		'.pure-u-2-3{width:66.6667%;box-sizing:border-box;}',
		'.block{margin:.5rem;padding:0;font-weight:normal;line-height:1;overflow-x:auto;border:1px solid rgba(0,0,0,.05);border-radius:.375rem;box-shadow:0 0 2rem 0 rgba(136,152,170,.15);}',
		'.img-con{margin:1rem;}',
		'.green{font-size:.9rem;color:#2dce89;}',
		'.red{font-size:.9rem;color:#fb6340;}',
		'.yellow{font-size:.9rem;color:#fb9a05;}',
		'.block img{width:48px;height:auto;}',
		'.block h4{font-size:.8125rem;font-weight:600;margin:1rem 0 1rem 1rem;color:#8898aa!important;line-height:1.8em;min-height:48px;}',
		'.check{cursor:pointer;}',
		'.pw-hidden-field{display:none !important;}',
		'.dns-con{padding:1rem;}',
		'.faq-title{color:var(--primary);font-weight:bolder;margin-bottom:.5rem;display:inline-block;}',
		'.reset-title{color:var(--primary);font-weight:bolder;margin-bottom:.3rem;display:inline-block;margin-top:1.2rem;text-decoration:underline;}',
		'.dns-item{margin-bottom:.8rem;line-height:1.2rem;}',
		'.dns-list{text-indent:1rem;line-height:1.2rem;}',
		'#cbi-passwall-socks .td.cbi-value-field > div{white-space:nowrap;}',
		'.up-modal{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);background:#fff;padding:20px;border:2px solid #ccc;border-radius:5px;box-shadow:0 0 10px rgba(0,0,0,.5);z-index:1000;width:90%;max-width:400px;}',
		'.up-modal-content{width:100%;max-width:400px;text-align:center;display:flex;flex-direction:column;justify-content:center;align-items:center;}',
		'.up-button-container{display:flex;justify-content:space-between;width:100%;max-width:250px;}',
		'.up-cbi-value-field{display:flex;flex-direction:column;align-items:center;width:100%;margin-top:15px;margin-bottom:30px;}',
		'.up-cbi-checkbox{display:flex;justify-content:space-between;align-items:center;width:100%;max-width:250px;margin:0 0 30px;}',
		'.up-cbi-checkbox label{display:flex;align-items:center;gap:5px;}',
		'@media (max-width:1152px){#cbi-passwall-socks .td.cbi-value-field > div{white-space:normal;}#cbi-passwall-socks .cbi-section-table-titles{display:none !important;}}',
		'@media screen and (max-width:720px){.block{margin:.2rem;}.pure-u-1-4{width:50%;}.pure-u-1-2{width:100%;}.block h4{margin:1rem 0 1rem .5rem;}}',
		'@media screen and (max-width:480px){.img-con{margin:1.5rem .5rem;}.block img{width:36px;}}'
	].join('\n'));
}

function statusCard(icon, id, title, initial, extra) {
	var spanAttrs = { 'class': 'red' };
	if (extra && extra.spanId)
		spanAttrs.id = extra.spanId;
	var h4 = E('h4', { 'id': id }, [
		title,
		E('br'),
		E('span', spanAttrs, initial)
	]);
	var block = E('div', { 'class': 'block pure-g' }, [
		E('div', { 'class': 'pure-u-1-3' }, [
			E('div', { 'class': 'img-con' }, [
				E('img', { 'src': icon, 'oncontextmenu': 'return false;', 'ondragstart': 'return false;' })
			])
		]),
		E('div', { 'class': 'pure-u-2-3' }, [ h4 ])
	]);
	var attrs = { 'class': 'pure-u-1-4' };
	if (extra && extra.check) {
		attrs.class = 'pure-u-1-4 check';
		attrs.title = _('HTTP request latency, for reference only');
		attrs.click = extra.check;
	}
	return E('div', attrs, [ block ]);
}

function renderStatus() {
	return E('fieldset', { 'id': '_passwall_status_fieldset', 'class': 'cbi-section' }, [
		E('legend', {}, _('Running Status')),
		E('div', { 'class': 'pure-g status' }, [
			statusCard(ICONS[0], 'status_tcp', 'TCP', _('NOT RUNNING')),
			statusCard(ICONS[1], 'status_udp', 'UDP', _('NOT RUNNING')),
			statusCard(ICONS[2], 'status_dns', 'DNS', _('NOT RUNNING')),
			statusCard(ICONS[3], 'status_haproxy', 'HAPROXY', 'N/A'),
			statusCard(ICONS[4], 'status_aliyun', _('AliCloud Conn.'), _('Touch Check'), {
				spanId: '_aliyun_status',
				check: function() { checkConnect('aliyun', 'https://www.aliyun.com/favicon.ico'); }
			}),
			statusCard(ICONS[5], 'status_google', _('Google Conn.'), _('Touch Check'), {
				spanId: '_google_status',
				check: function() { checkConnect('google', 'https://www.google.com/generate_204'); }
			}),
			statusCard(ICONS[6], 'status_github', _('GitHub Conn.'), _('Touch Check'), {
				spanId: '_github_status',
				check: function() { checkConnect('github', 'https://github.com/favicon.ico'); }
			}),
			statusCard(ICONS[7], 'status_youtube', _('YouTube Conn.'), _('Touch Check'), {
				spanId: '_youtube_status',
				check: function() { checkConnect('youtube', 'https://www.youtube.com/generate_204'); }
			})
		]),
		E('div', { 'id': 'status_now_node', 'class': 'cbi-section-descr' })
	]);
}

function setRun(id, label, on) {
	var el = document.getElementById(id);
	if (!el)
		return;
	while (el.firstChild)
		el.removeChild(el.firstChild);
	el.appendChild(document.createTextNode(label));
	el.appendChild(E('br'));
	el.appendChild(E('span', { 'class': on ? 'green' : 'red' }, on ? _('RUNNING') : _('NOT RUNNING')));
}

function paintIndex(data) {
	data = data || {};
	setRun('status_tcp', 'TCP', !!data.tcp_status);
	setRun('status_udp', 'UDP', !!data.udp_status);
	setRun('status_dns', 'DNS', !!data.dns_mode_status);
	var hp = document.getElementById('status_haproxy');
	if (!hp)
		return;
	while (hp.firstChild)
		hp.removeChild(hp.firstChild);
	hp.appendChild(document.createTextNode('HAPROXY'));
	hp.appendChild(E('br'));
	if (data.haproxy_status === '-1')
		hp.appendChild(E('span', { 'class': 'red' }, _('UNINSTALLED')));
	else if (data.haproxy_status === '0')
		hp.appendChild(E('span', { 'class': 'green' }, _('RUNNING')));
	else
		hp.appendChild(E('span', { 'class': 'red' }, _('NOT RUNNING')));
}

function checkConnect(type, url) {
	var s = document.getElementById('_' + type + '_status');
	if (!s)
		return;
	var card = s.parentNode && s.parentNode.parentNode && s.parentNode.parentNode.parentNode && s.parentNode.parentNode.parentNode.parentNode;
	if (card) {
		card.onclick = null;
		card.title = _('HTTP request latency, for reference only');
	}
	s.className = '';
	s.textContent = _('Check...');
	pw.get('connect_status', { url: url }).then(function(rv) {
		rv = rv || {};
		if (rv.ping_type && rv.ping_type === 'curl') {
			var use = parseFloat(rv.use_time);
			if (use < 1000)
				s.className = 'green';
			else if (use < 2000)
				s.className = 'yellow';
			else
				s.className = 'red';
			s.textContent = rv.use_time + ' ms';
			if (card)
				card.title += '\n' + _('Initial handshake time') + ': ' + rv.handshake_time + ' ms';
		}
		else if (rv.status) {
			s.className = 'green';
			s.textContent = _('Working...');
		}
		else {
			s.className = 'red';
			s.textContent = _('Problem detected!');
		}
		if (card)
			card.onclick = function() { checkConnect(type, url); };
	}).catch(function() {
		s.className = 'red';
		s.textContent = _('Problem detected!');
		if (card)
			card.onclick = function() { checkConnect(type, url); };
	});
}

function remarkNode(holder, remark) {
	while (holder.firstChild)
		holder.removeChild(holder.firstChild);
	var text = String(remark || '');
	if (!text)
		return;
	var parts = text.split('：[');
	if (parts.length === 1) {
		holder.textContent = text;
		return;
	}
	holder.appendChild(document.createTextNode(parts[0] + '：'));
	for (var i = 1; i < parts.length; i++) {
		holder.appendChild(E('br'));
		holder.appendChild(document.createTextNode('[' + parts[i]));
	}
}

function paintNowNode(data, remarks) {
	var el = document.getElementById('status_now_node');
	if (!el)
		return;
	var id = data && data.global;
	var remark = id ? (remarks[id] || id) : '';
	while (el.firstChild)
		el.removeChild(el.firstChild);
	if (!remark)
		return;
	el.appendChild(document.createTextNode(_('Current Node') + ': '));
	var span = E('span');
	remarkNode(span, remark);
	el.appendChild(span);
}

function paintSocksRuntime(cache, remarks) {
	document.querySelectorAll('[id^="pw-now-"]').forEach(function(holder) {
		var id = holder.getAttribute('data-socks-id');
		var nid = cache[id];
		remarkNode(holder, nid ? (remarks[nid] || nid) : '');
	});
}

function paintSocksPorts() {
	var rows = document.querySelectorAll('._socks_status');
	var jobs = [];
	for (var i = 0; i < rows.length; i++) {
		(function(el, index) {
			var id = el.getAttribute('socks_id');
			if (!id)
				return;
			jobs.push(pw.get('socks_status', { index: String(index), id: id }).then(function(result) {
				result = result || {};
				var socks = el.querySelector('._socks');
				var http = el.querySelector('._http');
				if (socks) {
					socks.textContent = result.socks_status ? '✓' : 'X';
					socks.style.fontWeight = 'bold';
					socks.style.color = result.socks_status ? 'green' : 'red';
				}
				if (http) {
					if (result.use_http) {
						http.textContent = result.http_status ? '✓' : 'X';
						http.style.fontWeight = 'bold';
						http.style.color = result.http_status ? 'green' : 'red';
					}
					else {
						http.textContent = '';
					}
				}
			}));
		})(rows[i], i);
	}
	return Promise.all(jobs);
}

function buildSelect(id, items, current) {
	var sel = E('select', { 'id': id, 'class': 'cbi-input-select', 'style': 'min-width:220px' });
	var groups = {};
	var order = [];
	var seen = {};
	items.forEach(function(it) {
		seen[it.value] = true;
		if (!it.group) {
			sel.appendChild(E('option', { 'value': it.value }, it.label));
			return;
		}
		if (!groups[it.group]) {
			groups[it.group] = [];
			order.push(it.group);
		}
		groups[it.group].push(it);
	});
	order.forEach(function(g) {
		var og = E('optgroup', { 'label': g });
		groups[g].forEach(function(it) {
			og.appendChild(E('option', { 'value': it.value }, it.label));
		});
		sel.appendChild(og);
	});
	if (current != null && current !== '' && !seen[current])
		sel.appendChild(E('option', { 'value': current }, current));
	if (current != null)
		sel.value = current;
	return sel;
}

function groupedNode(option, items, track) {
	items.forEach(function(it) {
		option.value(it.value, it.label);
	});
	option.formvalue = function(section_id) {
		var sel = document.getElementById(this.cbid(section_id));
		if (sel)
			return sel.value;
		var v = uci.get('passwall', section_id, this.option);
		return v == null ? '' : v;
	};
	option.write = function(section_id, value) {
		if (value == null || value === '') {
			if (this.rmempty !== false)
				return uci.unset('passwall', section_id, this.option);
		}
		return uci.set('passwall', section_id, this.option, value);
	};
	option.remove = function(section_id) {
		return uci.unset('passwall', section_id, this.option);
	};
	option.renderWidget = function(section_id, option_index, cfgvalue) {
		var self = this;
		var sel = buildSelect(this.cbid(section_id), items, cfgvalue == null ? '' : cfgvalue);
		sel.addEventListener('change', function(ev) {
			if (track && track.flag)
				track.flag(section_id, sel.value);
			if (typeof self.onchange === 'function')
				self.onchange(ev, section_id, sel.value);
		});
		return sel;
	};
	return option;
}

function setFlag(opt, section, on) {
	if (!opt)
		return;
	var el = opt.getUIElement(section);
	if (el && typeof el.setValue === 'function')
		el.setValue(!!on);
	else
		uci.set('passwall', section, opt.option, on ? '1' : '0');
}

function setList(opt, section, value) {
	if (!opt)
		return;
	var el = opt.getUIElement(section);
	if (el && typeof el.setValue === 'function')
		el.setValue(value);
	else
		uci.set('passwall', section, opt.option, value);
}

function logFileOption(option, path, exists, opener) {
	option.renderWidget = function() {
		var kids = [ E('code', {}, path), '\u00a0\u00a0' ];
		if (exists) {
			kids.push(E('input', {
				'class': 'btn cbi-button cbi-button-apply',
				'type': 'button',
				'value': _('View Log'),
				'click': function(ev) {
					ev.preventDefault();
					opener();
				}
			}));
		}
		return E('span', {}, kids);
	};
}

function getBg(el) {
	if (!el)
		return null;
	var style = window.getComputedStyle(el);
	var bgImage = style.backgroundImage;
	var bgColor = style.backgroundColor;
	if (bgImage !== 'none' || (!/rgba\([^,]+,[^,]+,[^,]+,\s*0\)/.test(bgColor) && bgColor !== 'transparent'))
		return style.background;
	return null;
}

function renderBackup() {
	var modal;
	var fileInput;
	var uploadBtn;

	function showUpload() {
		modal.style.background = getBg(document.querySelector('.cbi-section')) || getBg(document.body) || '';
		modal.style.display = 'block';
		fileInput.focus();
	}

	function closeUpload() {
		fileInput.value = '';
		modal.style.display = 'none';
	}

	function dlBackup() {
		return pw.call('create_backup').then(function(res) {
			if (!res || res.code === 0 || !res.filename || !res.output)
				throw new Error('备份失败！');
			var binary = atob(res.output);
			var bytes = new Uint8Array(binary.length);
			for (var i = 0; i < binary.length; i++)
				bytes[i] = binary.charCodeAt(i);
			var blob = new Blob([bytes], { 'type': 'application/gzip' });
			var url = window.URL.createObjectURL(blob);
			var a = E('a', { 'href': url, 'download': res.filename });
			document.body.appendChild(a);
			a.click();
			a.remove();
			window.URL.revokeObjectURL(url);
		}).catch(function(err) {
			alert(err.message || String(err));
		});
	}

	function doReset(type) {
		if (type !== 'client' && type !== 'server')
			return;
		var name = (type === 'client' ? _('Client') : _('Server')).toLowerCase();
		var message = tf('Do you want to restore the %s to default settings?', name);
		var confirmMessage = tf('Are you sure you want to restore the %s to default settings?', name);
		var redirect = type === 'client' ? pw.pageUrl('log') : pw.pageUrl('server');
		if (confirm(message)) {
			window.setTimeout(function() {
				if (confirm(confirmMessage)) {
					pw.call('reset_config', { type: type }).then(function() {
						window.location.href = redirect;
					});
				}
			}, 1000);
		}
	}

	function doUpload() {
		var client = modal.querySelector('input[name="client"]').checked;
		var server = modal.querySelector('input[name="server"]').checked;
		if (!client && !server)
			return;
		var type = (client === server) ? 'all' : (client ? 'client' : 'server');
		var file = fileInput.files && fileInput.files[0];
		if (!file) {
			alert(_('Please select a file first.'));
			return;
		}
		if (!file.name.endsWith('.tar.gz')) {
			alert(_('Invalid file type. Please upload a .tar.gz file.'));
			fileInput.value = '';
			return;
		}
		if (file.size > 10 * 1024 * 1024) {
			alert(_('File size exceeds 10MB limit.'));
			fileInput.value = '';
			return;
		}
		var reader = new FileReader();
		reader.onload = function(e) {
			var binary = new Uint8Array(e.target.result);
			var binaryText = '';
			var step = 4096;
			for (var i = 0; i < binary.length; i += step)
				binaryText += String.fromCharCode.apply(null, binary.subarray(i, i + step));
			var base64Data = btoa(binaryText);
			var targetByteSize = 64 * 1024;
			var chunkSize = Math.floor(targetByteSize * 4 / 3);
			chunkSize = chunkSize + (4 - (chunkSize % 4)) % 4;
			var totalChunks = Math.ceil(base64Data.length / chunkSize);
			var currentChunk = 0;
			var label = _('UL Restore');

			function sendNextChunk() {
				if (currentChunk >= totalChunks) {
					uploadBtn.value = label;
					window.location.href = (type === 'server') ? pw.pageUrl('server') : pw.pageUrl('log');
					return;
				}
				var chunk = base64Data.substring(currentChunk * chunkSize, (currentChunk + 1) * chunkSize);
				pw.call('restore_backup', {
					type: type,
					filename: file.name,
					chunk: chunk,
					chunk_index: String(currentChunk),
					total_chunks: String(totalChunks)
				}).then(function(resp) {
					resp = resp || {};
					if (resp.status === 'success') {
						currentChunk++;
						uploadBtn.value = 'Uploading... ' + Math.floor((currentChunk / totalChunks) * 100) + '%';
						sendNextChunk();
					}
					else {
						alert('Upload error: ' + (resp.message || ''));
						uploadBtn.value = label;
					}
				}).catch(function(err) {
					alert('Upload failed with status ' + (err && err.message ? err.message : err));
					uploadBtn.value = label;
				});
			}
			sendNextChunk();
		};
		reader.readAsArrayBuffer(file);
	}

	fileInput = E('input', { 'class': 'cbi-input-file', 'type': 'file', 'id': 'ulfile', 'accept': '.tar.gz' });
	uploadBtn = E('input', {
		'class': 'btn cbi-button cbi-button-apply',
		'type': 'button',
		'id': 'upload-btn',
		'value': _('UL Restore'),
		'click': doUpload
	});
	modal = E('div', { 'id': 'upload-modal', 'class': 'up-modal', 'style': 'display:none' }, [
		E('div', { 'class': 'up-modal-content' }, [
			E('h3', {}, _('Restore Backup File')),
			E('div', { 'class': 'up-cbi-value-field' }, [ fileInput ]),
			E('div', { 'class': 'up-cbi-checkbox' }, [
				E('label', {}, [
					E('input', { 'class': 'cbi-input-checkbox', 'type': 'checkbox', 'name': 'client', 'value': '1', 'checked': 'checked' }),
					_('Client')
				]),
				E('label', {}, [
					E('input', { 'class': 'cbi-input-checkbox', 'type': 'checkbox', 'name': 'server', 'value': '1' }),
					_('Server')
				])
			]),
			E('div', { 'class': 'up-button-container' }, [
				uploadBtn,
				E('input', {
					'class': 'btn cbi-button cbi-button-remove',
					'type': 'button',
					'value': _('CLOSE WIN'),
					'click': closeUpload
				})
			])
		])
	]);

	return E('div', {}, [
		E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Backup and Restore')),
			E('div', { 'class': 'cbi-section-descr' }, [
				_('Backup or Restore Client and Server Configurations.'),
				E('br'),
				E('font', { 'color': 'red' }, _('Note: Restoring configurations across different versions may cause compatibility issues.'))
			])
		]),
		E('div', { 'class': 'cbi-value', 'id': '_backup_div' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Create Backup File')),
			E('div', { 'class': 'cbi-value-field' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-save',
					'type': 'button',
					'value': _('DL Backup'),
					'click': dlBackup
				})
			])
		]),
		E('div', { 'class': 'cbi-value', 'id': '_upload_div' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Restore Backup File')),
			E('div', { 'class': 'cbi-value-field' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-apply',
					'type': 'button',
					'value': _('RST Backup'),
					'click': showUpload
				})
			])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, tf('Reset %s Configuration', _('Client'))),
			E('div', { 'class': 'cbi-value-field' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-reset',
					'type': 'button',
					'value': _('Do Reset'),
					'click': function() { doReset('client'); }
				})
			])
		]),
		E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, tf('Reset %s Configuration', _('Server'))),
			E('div', { 'class': 'cbi-value-field' }, [
				E('input', {
					'class': 'btn cbi-button cbi-button-reset',
					'type': 'button',
					'value': _('Do Reset'),
					'click': function() { doReset('server'); }
				})
			])
		]),
		modal
	]);
}

function renderFaq() {
	var hideUrl = window.location.origin + pw.pageUrl('hide');
	var showUrl = window.location.origin + pw.pageUrl('show');

	function hideMenu(ev) {
		if (ev)
			ev.preventDefault();
		if (confirm(_('Are you sure to hide?')) === true) {
			pw.call('hide_menu').then(function() {
				window.location.reload();
			});
		}
	}

	function showMenu(ev) {
		if (ev)
			ev.preventDefault();
		pw.call('show_menu').then(function() {
			window.location.reload();
		});
	}

	return E('div', { 'class': 'dns-con' }, [
		E('div', { 'id': 'faq_dns' }, [
			E('ul', {}, [
				E('b', { 'class': 'faq-title' }, _('DNS related issues:')),
				E('li', { 'class': 'dns-item' }, [
					'1. ',
					E('span', {}, _('Certain browsers such as Chrome have built-in DNS service, which may affect DNS resolution settings. You can go to \'Settings -> Privacy and security -> Use secure DNS\' menu to turn it off.'))
				]),
				E('li', { 'class': 'dns-item' }, [
					'2. ',
					E('span', {}, _('If you are unable to access the internet after reboot, please try clearing the cache of your terminal devices (make sure to close all open browser application windows first, this step is especially important):')),
					E('ul', {}, [
						E('li', { 'class': 'dns-list' }, [ ' ◦ ', E('span', {}, _('For Windows systems, open Command Prompt and run the command \'ipconfig /flushdns\'.')) ]),
						E('li', { 'class': 'dns-list' }, [ ' ◦ ', E('span', {}, _('For Mac systems, open Terminal and run the command \'sudo killall -HUP mDNSResponder\'.')) ]),
						E('li', { 'class': 'dns-list' }, [ ' ◦ ', E('span', {}, _('For mobile devices, you can clear it by reconnecting to the network, such as toggling Airplane Mode and reconnecting to WiFi.')) ])
					])
				]),
				E('li', { 'class': 'dns-item' }, [
					'3. ',
					E('span', {}, _('Please make sure your device\'s network settings point both the DNS server and default gateway to this router, to ensure DNS queries are properly routed.'))
				])
			])
		]),
		E('div', { 'id': 'faq_reset' }, [
			E('a', { 'href': '#', 'class': 'reset-title', 'click': hideMenu }, _(' Hide in main menu:')),
			E('br'),
			_(' Browser access: '),
			E('a', { 'href': '#', 'click': hideMenu }, hideUrl),
			E('br'),
			E('a', { 'href': '#', 'class': 'reset-title', 'click': showMenu }, _(' Show in main menu:')),
			E('br'),
			_(' Browser access: '),
			E('a', { 'href': '#', 'click': showMenu }, showUrl),
			E('br')
		])
	]);
}

function renderProxySwitch(section, flags) {
	function gfw() {
		setFlag(flags.use_gfw_list, section, true);
		setList(flags.chn_list, section, '0');
		setList(flags.tcp_proxy_mode, section, 'disable');
		setList(flags.udp_proxy_mode, section, 'disable');
	}
	function chn() {
		setFlag(flags.use_gfw_list, section, true);
		setList(flags.chn_list, section, 'direct');
		setList(flags.tcp_proxy_mode, section, 'proxy');
		setList(flags.udp_proxy_mode, section, 'proxy');
	}
	function home() {
		setFlag(flags.use_gfw_list, section, false);
		setList(flags.chn_list, section, 'proxy');
		setList(flags.tcp_proxy_mode, section, 'disable');
		setList(flags.udp_proxy_mode, section, 'disable');
	}
	function globalMode() {
		setFlag(flags.use_gfw_list, section, false);
		setList(flags.chn_list, section, '0');
		setList(flags.tcp_proxy_mode, section, 'proxy');
		setList(flags.udp_proxy_mode, section, 'proxy');
	}
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, _('Switch Mode')),
		E('div', { 'class': 'cbi-value-field' }, [
			E('div', {}, [
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('GFW List'), 'click': gfw }),
				' ',
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('Not China List'), 'click': chn }),
				' ',
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('China List'), 'click': home }),
				' ',
				E('input', { 'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'value': _('Global Proxy'), 'click': globalMode })
			])
		])
	]);
}

function missingProxyWidget() {
	return E('div', {}, [
		E('div', { 'class': 'cbi-checkbox' }, [
			E('input', { 'class': 'cbi-input-checkbox', 'type': 'checkbox', 'disabled': 'disabled' })
		]),
		E('div', { 'class': 'cbi-value-description' }, [
			E('font', { 'color': 'red' }, _('Missing components, transparent proxy is unavailable.'))
		])
	]);
}

function fileExists(path) {
	return fs.stat(path).then(function() {
		return true;
	}).catch(function() {
		return false;
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('passwall'),
			pw.loadCaps(),
			fileExists(LOG_GLOBAL),
			fileExists(LOG_CHINA),
			fileExists(LOG_SMART),
			fs.read(CACHE_VAR).catch(function() { return ''; })
		]);
	},

	render: function(data) {
		var caps = data[1] || {};
		var nodes = caps.nodes || [];
		var nodeList = caps.node_list || {};
		var logGlobal = !!data[2];
		var logChina = !!data[3];
		var logSmart = !!data[4];
		var cacheText = data[5] || '';
		var globals = uci.sections('passwall', 'global') || [];
		var sid = globals.length ? globals[0]['.name'] : pw.sectionId('passwall', 'global');
		var remarks = {};
		nodes.forEach(function(n) {
			remarks[nodeIdOf(n)] = n.remark || '';
		});

		var rootKids = [ pageStyle(), renderStatus() ];
		if (!sid) {
			rootKids.push(E('div', { 'class': 'alert-message warning' }, _('Global') ));
			return E('div', {}, rootKids);
		}

		var loadedNode = uci.get('passwall', sid, 'node') || '';
		var nodeById = function(id) {
			for (var i = 0; i < nodes.length; i++)
				if (nodeIdOf(nodes[i]) === id)
					return nodes[i];
			return null;
		};
		var loadedObj = nodeById(loadedNode);
		var nodeSaveBefore = loadedObj ? nodeIdOf(loadedObj) : '';
		var hasCore = present(caps.singbox) || present(caps.xray);
		var normalCount = (nodeList.normal_list || []).length;
		var ifaceCount = (nodeList.iface_list || []).length;
		var hasNodes = nodes.length > 0;
		var hasNormal = normalCount > 0 || ifaceCount > 0;
		var showShunt = hasCore && hasNodes && hasNormal && loadedObj && loadedObj.protocol === '_shunt';
		var showNoNodeTip = hasCore && hasNodes && !hasNormal;
		var shuntIds = {};
		var mods = caps.lsmod || '';
		var transparent = (mods.indexOf('REDIRECT') >= 0 && mods.indexOf('TPROXY') >= 0) ||
			(mods.indexOf('nft_redir') >= 0 && mods.indexOf('nft_tproxy') >= 0);

		var m = new form.Map('passwall', '', '');
		var s = m.section(form.NamedSection, sid, 'global');
		s.tab('Main', _('Main'));
		if (showShunt)
			s.tab('Shunt', _('Shunt Rule'));
		s.tab('DNS', _('DNS'));
		s.tab('Proxy', _('Mode'));
		s.tab('log', _('Log'));
		s.tab('faq', 'FAQ');
		s.tab('maintain', _('Maintain'));
		s.tab('socks', _('Socks Config'));

		var o;
		o = s.taboption('Main', form.Flag, 'enabled', _('Main switch'));
		o.rmempty = false;

		var nodeOpt = s.taboption('Main', form.ListValue, 'node', E('a', { 'style': 'color: red' }, _('Proxy Node')));
		var shuntSel = s.taboption('Main', form.Value, '_node_sel_shunt', '');
		shuntSel.depends({ node: '__always__' });
		shuntSel.write = function() {};
		shuntSel.remove = function() {};
		shuntSel.formvalue = function(section_id) {
			var input = document.getElementById(this.cbid(section_id));
			if (input)
				return input.value;
			return shuntIds[uci.get('passwall', section_id, 'node')] ? '1' : '';
		};
		shuntSel.render = function(section_id) {
			var value = shuntIds[uci.get('passwall', section_id, 'node')] ? '1' : '';
			return E('div', { 'class': 'pw-hidden-field', 'id': 'cbi-passwall-' + section_id + '-_node_sel_shunt' }, [
				E('input', { 'type': 'hidden', 'id': this.cbid(section_id), 'value': value })
			]);
		};

		function setShuntFlag(section_id, nodeValue) {
			var input = document.getElementById(shuntSel.cbid(section_id));
			if (input)
				input.value = shuntIds[nodeValue] ? '1' : '';
			var tab = document.getElementById('tab.passwall.' + sid + '.Shunt');
			var on = !!shuntIds[nodeValue] && nodeValue === (loadedObj ? nodeIdOf(loadedObj) : '');
			if (tab && tab.parentNode && tab.parentNode.tagName === 'LI')
				tab.parentNode.style.display = on ? '' : 'none';
		}

		if (showNoNodeTip) {
			o = s.taboption('Main', form.DummyValue, 'tips', '　');
			o.depends({ node: '', '!reverse': true });
			o.renderWidget = function() {
				return E('a', { 'style': 'color: red' }, _('There are no available nodes, please add or subscribe nodes first.'));
			};
		}

		o = s.taboption('Main', form.Value, 'node_socks_port', _('Node') + ' Socks ' + _('Listen Port'));
		o.default = '1070';
		o.placeholder = '1070';
		o.datatype = 'range(1,65535)';
		o.depends({ node: '', '!reverse': true });

		o = s.taboption('Main', form.Flag, 'node_socks_bind_local', _('Node') + ' Socks ' + _('Bind Local'), _('When selected, it can only be accessed localhost.'));
		o.default = '1';
		o.depends({ node: '', '!reverse': true });

		var nodeBefore = s.taboption('Main', form.DummyValue, 'node_save_before', '');
		nodeBefore.render = function() {
			return E('div', { 'class': 'pw-hidden-field' }, [
				E('input', { 'type': 'hidden', 'name': 'node_save_before', 'id': 'node_save_before', 'value': nodeSaveBefore })
			]);
		};

		var dnsShunt = s.taboption('DNS', form.ListValue, 'dns_shunt', 'DNS ' + _('Shunt'));
		dnsShunt.value('dnsmasq', 'Dnsmasq');
		dnsShunt.value('chinadns-ng', _('ChinaDNS-NG (recommended)'));
		if (present(caps.smartdns))
			dnsShunt.value('smartdns', 'SmartDNS');
		dnsShunt.write = function(section, value) {
			var old = uci.get('passwall', section, 'dns_shunt');
			if (old && old !== value)
				uci.set('passwall', section, 'flush_set', '1');
			return form.ListValue.prototype.write.apply(this, arguments);
		};

		var directMode = s.taboption('DNS', form.ListValue, 'direct_dns_mode', _('Direct DNS') + ' ' + _('Request protocol'));
		directMode.value('', _('Auto'));
		directMode.value('udp', tf('Requery DNS By %s', 'UDP'));
		directMode.value('tcp', tf('Requery DNS By %s', 'TCP'));
		directMode.depends({ dns_shunt: 'dnsmasq' });
		directMode.depends({ dns_shunt: 'chinadns-ng' });

		o = s.taboption('DNS', form.Value, 'direct_dns', _('Direct DNS'));
		o.datatype = 'or(ipaddr,ipaddrport(1))';
		o.default = '223.5.5.5';
		['223.5.5.5', '223.6.6.6', '180.184.1.1', '180.184.2.2', '114.114.114.114', '114.114.115.115', '119.28.28.28'].forEach(function(v) {
			o.value(v);
		});
		o.depends({ dns_shunt: 'dnsmasq', direct_dns_mode: 'udp' });
		o.depends({ dns_shunt: 'dnsmasq', direct_dns_mode: 'tcp' });
		o.depends({ dns_shunt: 'chinadns-ng', direct_dns_mode: 'udp' });
		o.depends({ dns_shunt: 'chinadns-ng', direct_dns_mode: 'tcp' });

		if (present(caps.smartdns)) {
			o = s.taboption('DNS', form.DynamicList, 'smartdns_direct_dns', _('Direct DNS'));
			o.placeholder = _('Auto');
			o.rmempty = true;
			['223.5.5.5', '119.29.29.29', 'tcp://223.5.5.5', 'tcp://114.114.114.114', 'tls://dot.pub,1.12.12.12', 'tls://dns.alidns.com,223.5.5.5', 'https://223.5.5.5/dns-query', 'https://1.12.12.12/dns-query'].forEach(function(v) {
				o.value(v);
			});
			o.depends({ dns_shunt: 'smartdns' });
		}

		o = s.taboption('DNS', form.Flag, 'filter_proxy_ipv6', _('Filter Proxy Host IPv6'));
		o.default = '0';

		var dnsMode = s.taboption('DNS', form.ListValue, 'dns_mode', _('Filter Mode'));
		dnsMode.default = 'tcp';
		dnsMode.value('udp', tf('Requery DNS By %s', 'UDP'));
		dnsMode.value('tcp', tf('Requery DNS By %s', 'TCP'));
		if (present(caps.dns2socks))
			dnsMode.value('dns2socks', 'dns2socks');
		if (present(caps.singbox))
			dnsMode.value('sing-box', 'Sing-Box');
		if (present(caps.xray))
			dnsMode.value('xray', 'Xray');
		dnsMode.depends({ dns_shunt: 'chinadns-ng', _node_sel_shunt: '' });
		dnsMode.depends({ dns_shunt: 'dnsmasq', _node_sel_shunt: '' });

		var smartdnsMode = null;
		if (present(caps.smartdns)) {
			smartdnsMode = s.taboption('DNS', form.ListValue, 'smartdns_dns_mode', _('Filter Mode'));
			smartdnsMode.value('socks', 'Socks');
			if (present(caps.singbox))
				smartdnsMode.value('sing-box', 'Sing-Box');
			if (present(caps.xray))
				smartdnsMode.value('xray', 'Xray');
			smartdnsMode.depends({ dns_shunt: 'smartdns', _node_sel_shunt: '' });
			smartdnsMode.write = function(section, value) {
				if (value === 'socks')
					uci.unset('passwall', section, 'v2ray_dns_mode');
				return form.ListValue.prototype.write.apply(this, arguments);
			};
		}

		var xrayDns = s.taboption('DNS', form.ListValue, 'xray_dns_mode', _('Remote DNS') + ' ' + _('Request protocol'));
		xrayDns.default = 'tcp';
		xrayDns.value('tcp', 'TCP');
		xrayDns.value('udp', 'UDP');
		xrayDns.value('doh', 'DoH');
		xrayDns.depends('dns_mode', 'xray');
		xrayDns.depends('smartdns_dns_mode', 'xray');
		xrayDns.cfgvalue = function(section) {
			return uci.get('passwall', section, 'v2ray_dns_mode');
		};
		xrayDns.write = function(section, value) {
			var sm = smartdnsMode && smartdnsMode.formvalue(section);
			if (dnsMode.formvalue(section) === 'xray' || sm === 'xray')
				uci.set('passwall', section, 'v2ray_dns_mode', value);
		};

		var singDns = s.taboption('DNS', form.ListValue, 'singbox_dns_mode', _('Remote DNS') + ' ' + _('Request protocol'));
		singDns.default = 'tcp';
		singDns.value('tcp', 'TCP');
		singDns.value('udp', 'UDP');
		singDns.value('doh', 'DoH');
		singDns.value('http3', 'HTTP3(DoH3)');
		singDns.value('tls', 'TLS(DoT)');
		singDns.value('quic', 'QUIC(DoQ)');
		singDns.depends('dns_mode', 'sing-box');
		singDns.depends('smartdns_dns_mode', 'sing-box');
		singDns.cfgvalue = function(section) {
			return uci.get('passwall', section, 'v2ray_dns_mode');
		};
		singDns.write = function(section, value) {
			var sm = smartdnsMode && smartdnsMode.formvalue(section);
			if (dnsMode.formvalue(section) === 'sing-box' || sm === 'sing-box')
				uci.set('passwall', section, 'v2ray_dns_mode', value);
		};

		function dnsModeSave(section) {
			var idVal = nodeOpt.formvalue(section) || '';
			if (!idVal)
				return;
			var node = nodeById(idVal);
			if (!node || node.protocol !== '_shunt')
				return;
			var typeVal = node.type;
			if (typeVal !== 'Xray' && typeVal !== 'sing-box')
				return;
			var dnsShuntVal = dnsShunt.formvalue(section);
			var key = (dnsShuntVal !== 'smartdns') ? 'dns_mode' : 'smartdns_dns_mode';
			var currentVal = uci.get('passwall', section, key) || '';
			var newVal = (typeVal === 'Xray') ? 'xray' : 'sing-box';
			if (currentVal !== newVal) {
				uci.set('passwall', section, key, newVal);
				uci.unset('passwall', section, key === 'dns_mode' ? 'smartdns_dns_mode' : 'dns_mode');
			}
			var field = (typeVal === 'Xray') ? xrayDns : singDns;
			var v2 = field && field.formvalue(section);
			if (v2 && uci.get('passwall', section, 'v2ray_dns_mode') !== v2)
				uci.set('passwall', section, 'v2ray_dns_mode', v2);
		}

		dnsMode.write = function(section, value) {
			if (value !== 'sing-box' && value !== 'xray')
				uci.unset('passwall', section, 'v2ray_dns_mode');
			return form.ListValue.prototype.write.apply(this, arguments);
		};
		dnsMode.remove = function(section) {
			if (smartdnsMode && smartdnsMode.formvalue(section))
				return uci.unset('passwall', section, 'dns_mode');
			dnsModeSave(section);
		};
		if (smartdnsMode) {
			smartdnsMode.remove = function(section) {
				if (dnsMode.formvalue(section))
					return uci.unset('passwall', section, 'smartdns_dns_mode');
				dnsModeSave(section);
			};
			o = s.taboption('DNS', form.DynamicList, 'smartdns_remote_dns', _('Remote DNS'));
			['tcp://1.1.1.1', 'tcp://8.8.4.4', 'tcp://8.8.8.8', 'tcp://9.9.9.9', 'tcp://208.67.222.222', 'tls://1.1.1.1', 'tls://8.8.4.4', 'tls://8.8.8.8', 'tls://9.9.9.9', 'tls://208.67.222.222', 'https://1.1.1.1/dns-query', 'https://8.8.4.4/dns-query', 'https://8.8.8.8/dns-query', 'https://9.9.9.9/dns-query', 'https://208.67.222.222/dns-query', 'https://dns.adguard.com/dns-query,94.140.14.14', 'https://doh.libredns.gr/dns-query,116.202.176.26', 'https://doh.libredns.gr/ads,116.202.176.26'].forEach(function(v) {
				o.value(v);
			});
			o.depends({ dns_shunt: 'smartdns', smartdns_dns_mode: 'socks' });
			o.cfgvalue = function(section) {
				var v = uci.get('passwall', section, 'smartdns_remote_dns');
				if (v == null || v === '')
					return ['tcp://1.1.1.1'];
				return v;
			};
		}

		var socksPort = uci.get('passwall', sid, 'node_socks_port') || '1070';
		var socksTable = [{
			id: '127.0.0.1:' + socksPort,
			remark: '127.0.0.1:' + socksPort + ' - ' + _('Proxy Node')
		}];
		(uci.sections('passwall', 'socks') || []).forEach(function(sec) {
			if (String(sec.enabled) === '1' && sec.node) {
				var remark = null;
				nodes.forEach(function(n) {
					if (sec.node === nodeIdOf(n))
						remark = n.remark;
				});
				var id = '127.0.0.1:' + sec.port;
				socksTable.push({
					id: id,
					remark: id + ' - ' + (remark || _('Misconfigured'))
				});
			}
		});

		o = s.taboption('DNS', form.Value, 'socks_server', _('Socks Server'), _('Make sure socks service is available on this address.'));
		socksTable.forEach(function(v) {
			o.value(v.id, v.remark);
		});
		o.default = socksTable[0].id;
		o.datatype = 'ipaddrport';
		o.validate = function(section, value) {
			if (!isIpAddrPort(value))
				return _('Socks Server') + ' ' + _('Not valid IP format, please re-enter!');
			return true;
		};
		o.depends({ dns_mode: 'dns2socks' });

		o = s.taboption('DNS', form.Value, 'remote_dns', _('Remote DNS'));
		o.datatype = 'or(ipaddr,ipaddrport(1))';
		o.default = '1.1.1.1';
		o.value('1.1.1.1', '1.1.1.1 (CloudFlare)');
		o.value('1.1.1.2', '1.1.1.2 (CloudFlare-Security)');
		o.value('8.8.4.4', '8.8.4.4 (Google)');
		o.value('8.8.8.8', '8.8.8.8 (Google)');
		o.value('9.9.9.9', '9.9.9.9 (Quad9)');
		o.value('149.112.112.112', '149.112.112.112 (Quad9)');
		o.value('208.67.220.220', '208.67.220.220 (OpenDNS)');
		o.value('208.67.222.222', '208.67.222.222 (OpenDNS)');
		o.depends({ dns_mode: 'dns2socks' });
		o.depends({ dns_mode: 'tcp' });
		o.depends({ dns_mode: 'udp' });
		o.depends({ xray_dns_mode: 'udp' });
		o.depends({ xray_dns_mode: 'tcp' });
		o.depends({ singbox_dns_mode: 'udp' });
		o.depends({ singbox_dns_mode: 'tcp' });
		o.depends({ singbox_dns_mode: 'tls' });
		o.depends({ singbox_dns_mode: 'quic' });

		o = s.taboption('DNS', form.Value, 'remote_dns_doh', _('Remote DNS DoH'));
		o.description = _('Format: URL[,IP] (optional IP to map the domain in the URL)');
		o.value('https://1.1.1.1/dns-query', '1.1.1.1 (CloudFlare)');
		o.value('https://1.1.1.2/dns-query', '1.1.1.2 (CloudFlare-Security)');
		o.value('https://8.8.4.4/dns-query', '8.8.4.4 (Google)');
		o.value('https://8.8.8.8/dns-query', '8.8.8.8 (Google)');
		o.value('https://9.9.9.9/dns-query', '9.9.9.9 (Quad9)');
		o.value('https://149.112.112.112/dns-query', '149.112.112.112 (Quad9)');
		o.value('https://208.67.222.222/dns-query', '208.67.222.222 (OpenDNS)');
		o.value('https://dns.adguard.com/dns-query,94.140.14.14', '94.140.14.14 (AdGuard)');
		o.value('https://doh.libredns.gr/dns-query,116.202.176.26', '116.202.176.26 (LibreDNS)');
		o.value('https://doh.libredns.gr/ads,116.202.176.26', '116.202.176.26 (LibreDNS-NoAds)');
		o.default = 'https://1.1.1.1/dns-query';
		o.validate = function(section, value) {
			var cleaned = String(value || '').replace(/\s+/g, '');
			if (cleaned !== '') {
				var parts = cleaned.split(',');
				var ok = true;
				for (var i = 1; i < parts.length; i++) {
					if (parts[i] && !isIpMask4(parts[i]) && !isIpMask6(parts[i]))
						ok = false;
				}
				if (ok)
					return true;
			}
			return tf('%s request address', 'DoH') + ' ' + _('Format must be:') + ' URL,IP';
		};
		o.depends({ xray_dns_mode: 'doh' });
		o.depends({ singbox_dns_mode: 'doh' });
		o.depends({ singbox_dns_mode: 'http3' });

		o = s.taboption('DNS', form.Value, 'remote_dns_client_ip', _('EDNS Client Subnet'));
		o.description = E('div', {}, [
			_('Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).'),
			E('br'),
			_('This feature requires the DNS server to support the Edns Client Subnet (RFC7871).')
		]);
		o.datatype = 'ipaddr';
		o.depends({ dns_mode: 'sing-box' });
		o.depends({ dns_mode: 'xray' });
		o.depends('dns_shunt', 'smartdns');
		o.depends('_node_sel_shunt', '1');

		o = s.taboption('DNS', form.Flag, 'remote_fakedns', 'FakeDNS', _('Use FakeDNS work in the domain that proxy.'));
		o.default = '0';
		o.depends({ dns_mode: 'sing-box', dns_shunt: 'dnsmasq' });
		o.depends({ dns_mode: 'sing-box', dns_shunt: 'chinadns-ng' });
		o.depends({ smartdns_dns_mode: 'sing-box', dns_shunt: 'smartdns' });
		o.depends({ dns_mode: 'xray', dns_shunt: 'dnsmasq' });
		o.depends({ dns_mode: 'xray', dns_shunt: 'chinadns-ng' });
		o.depends({ smartdns_dns_mode: 'xray', dns_shunt: 'smartdns' });
		o.validate = function(section, value) {
			if (String(value) === '1') {
				var mode = dnsMode.formvalue(section);
				if (!mode && smartdnsMode)
					mode = smartdnsMode.formvalue(section);
				var nid = nodeOpt.formvalue(section);
				if (mode && nid) {
					var n = nodeById(nid);
					var ntype = String((n && n.type) || '').toLowerCase();
					if (ntype !== String(mode).toLowerCase() && String(nid).indexOf('socks_') < 0)
						return tf('Node must be \'%s\' type to use FakeDNS.', mode);
				}
			}
			return true;
		};

		var rewriteTtl = s.taboption('DNS', form.Value, 'remote_rewrite_ttl', _('Remote DNS') + ' TTL');
		rewriteTtl.datatype = 'min(1)';
		rewriteTtl.default = '30';
		rewriteTtl.depends({ dns_mode: 'sing-box', dns_shunt: 'dnsmasq' });
		rewriteTtl.depends({ dns_mode: 'sing-box', dns_shunt: 'chinadns-ng' });
		rewriteTtl.depends({ smartdns_dns_mode: 'sing-box', dns_shunt: 'smartdns' });

		o = s.taboption('DNS', form.ListValue, 'chinadns_ng_default_tag', _('Default DNS'));
		o.default = 'none';
		o.value('gfw', _('Remote DNS'));
		o.value('chn', _('Direct DNS'));
		o.value('none', _('Smart, Do not accept no-ip reply from Direct DNS'));
		o.value('none_noip', _('Smart, Accept no-ip reply from Direct DNS'));
		o.description = ul(smartDnsLines());
		o.depends({ dns_shunt: 'chinadns-ng', tcp_proxy_mode: 'proxy', chn_list: 'direct' });

		o = s.taboption('DNS', form.ListValue, 'use_default_dns', _('Default DNS'));
		o.default = 'direct';
		o.value('remote', _('Remote DNS'));
		o.value('direct', _('Direct DNS'));
		o.description = ul(baseDnsLines());
		o.depends({ dns_shunt: 'dnsmasq', tcp_proxy_mode: 'proxy', chn_list: 'direct' });

		if (present(caps.smartdns)) {
			o = s.taboption('DNS', form.ListValue, 'smartdns_default_dns', _('Default DNS'));
			o.default = 'direct';
			o.value('remote', _('Remote DNS'));
			o.value('direct', _('Direct DNS'));
			o.value('auto', _('Auto'));
			o.description = ul(baseDnsLines().concat([
				_('Auto: Prefer mainland China IPs returned by direct DNS and fall back to remote DNS when no usable result is available.')
			]));
			o.depends({ dns_shunt: 'smartdns', tcp_proxy_mode: 'proxy', chn_list: 'direct' });
		}

		o = s.taboption('DNS', form.Flag, 'force_https_soa', _('Force HTTPS SOA'), _('Force queries with qtype 65 to respond with an SOA record.'));
		o.default = '0';
		o.depends({ dns_shunt: 'chinadns-ng' });
		if (present(caps.smartdns))
			o.depends({ dns_shunt: 'smartdns' });

		o = s.taboption('DNS', form.Flag, 'dns_redirect', _('DNS Redirect'), _('Force special DNS server to need proxy devices.'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('DNS', form.Flag, 'flush_set_on_reboot', _('Clear NFTSET on Reboot'), _('Clear NFTSET on service reboot. This may increase reboot time.'));
		o.default = '0';

		o = s.taboption('DNS', form.DummyValue, 'clear_nftset', _('Clear NFTSET'), _('Try this feature if the rule modification does not take effect.'));
		o.renderWidget = function() {
			return E('button', {
				'class': 'cbi-button cbi-button-remove',
				'type': 'button',
				'click': function(ev) {
					ev.preventDefault();
					return pw.call('flush_set', { redirect: '1', reload: '1' }).then(function() {
						window.location.reload();
					});
				}
			}, clearTitle);
		};

		o = s.taboption('Proxy', form.Flag, 'use_direct_list', tf('Use %s', _('Direct List')));
		o.default = '1';
		o = s.taboption('Proxy', form.Flag, 'use_proxy_list', tf('Use %s', _('Proxy List')));
		o.default = '1';
		o = s.taboption('Proxy', form.Flag, 'use_block_list', tf('Use %s', _('Block List')));
		o.default = '1';
		var useGfw = null;
		if (caps.has_gfwlist) {
			useGfw = s.taboption('Proxy', form.Flag, 'use_gfw_list', tf('Use %s', _('GFW List')));
			useGfw.default = '1';
		}
		var chnList = null;
		if (caps.has_chnlist || caps.has_chnroute) {
			chnList = s.taboption('Proxy', form.ListValue, 'chn_list', _('China List'));
			chnList.value('0', _('Close(Not use)'));
			chnList.value('direct', _('Direct Connection'));
			chnList.value('proxy', _('Proxy'));
			chnList.default = 'direct';
		}
		var tcpMode = s.taboption('Proxy', form.ListValue, 'tcp_proxy_mode', 'TCP ' + _('Default Proxy Mode'));
		tcpMode.value('disable', _('No Proxy'));
		tcpMode.value('proxy', _('Proxy'));
		tcpMode.default = 'proxy';
		var udpMode = s.taboption('Proxy', form.ListValue, 'udp_proxy_mode', 'UDP ' + _('Default Proxy Mode'));
		udpMode.value('disable', _('No Proxy'));
		udpMode.value('proxy', _('Proxy'));
		udpMode.default = 'proxy';

		o = s.taboption('Proxy', form.DummyValue, 'switch_mode', '');
		o.render = function() {
			return renderProxySwitch(sid, {
				use_gfw_list: useGfw,
				chn_list: chnList,
				tcp_proxy_mode: tcpMode,
				udp_proxy_mode: udpMode
			});
		};

		if (transparent) {
			o = s.taboption('Proxy', form.Flag, 'localhost_proxy', _('Localhost Proxy'), _('When selected, localhost can transparent proxy.'));
			o.default = '1';
			o.rmempty = false;
			o = s.taboption('Proxy', form.Flag, 'client_proxy', _('Client Proxy'), _('When selected, devices in LAN can transparent proxy. Otherwise, it will not be proxy. But you can still use access control to allow the designated device to proxy.'));
			o.default = '1';
			o.rmempty = false;
		}
		else {
			o = s.taboption('Proxy', form.DummyValue, 'localhost_proxy', _('Localhost Proxy'));
			o.renderWidget = function() { return missingProxyWidget(); };
			o = s.taboption('Proxy', form.DummyValue, 'client_proxy', _('Client Proxy'));
			o.renderWidget = function() { return missingProxyWidget(); };
		}

		o = s.taboption('Proxy', form.DummyValue, '_proxy_tips', '　');
		o.renderWidget = function() {
			return E('a', {
				'style': 'color: red',
				'href': pw.pageUrl('acl')
			}, _('Want different devices to use different proxy modes/ports/nodes? Please use access control.'));
		};

		o = s.taboption('log', form.Flag, 'log_node', _('Enable Node Log'));
		o.default = '0';
		o.rmempty = false;
		o = s.taboption('log', form.ListValue, 'loglevel', _('Log Level'));
		o.default = 'warn';
		o.value('debug', 'Debug');
		o.value('info', 'Info');
		o.value('warn', 'Warning');
		o.value('error', 'Error');
		o = s.taboption('log', form.DummyValue, '_node_log', _('Log File'));
		o.depends('log_node', '1');
		logFileOption(o, LOG_GLOBAL, logGlobal, function() {
			return openLog(pw.get('get_redir_log', { id: 'default' }));
		});

		o = s.taboption('log', form.Flag, 'log_chinadns_ng', _('Enable') + ' ChinaDNS-NG ' + _('Log'));
		o.default = '0';
		o.rmempty = false;
		o.depends('dns_shunt', 'chinadns-ng');
		o = s.taboption('log', form.DummyValue, '_chinadns_ng_log', _('Log File'));
		o.depends('log_chinadns_ng', '1');
		logFileOption(o, LOG_CHINA, logChina, function() {
			return openLog(pw.get('get_chinadns_log', { flag: 'default' }));
		});

		if (present(caps.smartdns)) {
			o = s.taboption('log', form.Flag, 'log_smartdns', _('Enable') + ' SmartDNS ' + _('Log'));
			o.default = '0';
			o.rmempty = false;
			o.depends('dns_shunt', 'smartdns');
			o = s.taboption('log', form.ListValue, 'smartdns_log_level', 'SmartDNS ' + _('Log Level'));
			o.default = 'error';
			o.value('fatal', 'Fatal');
			o.value('error', 'Error');
			o.value('warn', 'Warning');
			o.value('notice', 'Notice');
			o.value('info', 'Info');
			o.value('debug', 'Debug');
			o.depends('log_smartdns', '1');
			o = s.taboption('log', form.Value, 'smartdns_log_size', _('Log Size') + ' (MB)');
			o.default = '1';
			o.datatype = 'and(uinteger,min(1))';
			o.depends('log_smartdns', '1');
			o = s.taboption('log', form.DummyValue, '_smartdns_log', _('Log File'));
			o.depends('log_smartdns', '1');
			logFileOption(o, LOG_SMART, logSmart, function() {
				return openLog(pw.get('get_smartdns_log'));
			});
			if (caps.has_smartdns_ui) {
				o = s.taboption('log', form.Flag, 'smartdns_ui', 'SmartDNS ' + _('Enable WebUI'));
				o.default = '0';
				o.rmempty = false;
				o.depends('dns_shunt', 'smartdns');
				var uiPort = s.taboption('log', form.Value, 'smartdns_ui_port', _('WebUI Port'));
				uiPort.default = '9880';
				uiPort.datatype = 'range(1,65535)';
				uiPort.depends('smartdns_ui', '1');
				o = s.taboption('log', form.Value, 'smartdns_ui_data_dir', _('WebUI Database Directory'));
				o.default = TMP + '_tmp/smartdns';
				o.depends('smartdns_ui', '1');
				o.validate = function(section, value) {
					value = String(value == null ? '' : value).replace(/^\s+|\s+$/g, '');
					if (value.charAt(0) !== '/' || /\s/.test(value))
						return _('An absolute path without spaces is required.');
					return true;
				};
				o = s.taboption('log', form.Value, 'smartdns_ui_log_max_age', _('WebUI Log Retention Days'));
				o.default = '7';
				o.datatype = 'and(uinteger,min(1))';
				o.depends('smartdns_ui', '1');
				o = s.taboption('log', form.DummyValue, '_smartdns_ui_link', 'WebUI');
				o.depends('smartdns_ui', '1');
				o.renderWidget = function() {
					return E('input', {
						'class': 'btn cbi-button cbi-button-apply',
						'type': 'button',
						'value': _('Open WebUI'),
						'click': function(ev) {
							ev.preventDefault();
							var port = parseInt(uiPort.formvalue(sid), 10);
							if (!(port >= 1 && port <= 65535))
								port = 9880;
							var host = window.location.hostname;
							if (host.indexOf(':') !== -1 && host.charAt(0) !== '[')
								host = '[' + host + ']';
							window.open('http://' + host + ':' + port, '_blank', 'noopener,noreferrer');
						}
					});
				};
			}
		}

		o = s.taboption('log', form.DummyValue, '_log_tips', '　');
		o.renderWidget = function() {
			return E('font', { 'color': 'red' }, _('It is recommended to disable logging during regular use to reduce system overhead.'));
		};

		o = s.taboption('faq', form.DummyValue, '_faq', '');
		o.render = function() { return renderFaq(); };

		o = s.taboption('maintain', form.DummyValue, '_backup', '');
		o.render = function() { return renderBackup(); };

		var socksAnchor = s.taboption('socks', form.DummyValue, '_socks_anchor', '');
		socksAnchor.render = function() { return E('div', { 'id': 'pw-socks-anchor' }); };

		o = s.taboption('Main', form.Flag, 'socks_enabled', 'Socks ' + _('Main switch'));
		o.rmempty = false;

		var shuntNodeId = showShunt ? nodeIdOf(loadedObj) : '';
		function mirror(option, uciName, asFlag) {
			option.cfgvalue = function() {
				return uci.get('passwall', shuntNodeId, uciName);
			};
			option.write = function(section, value) {
				uci.unset('passwall', section, option.option);
				if (nodeOpt.formvalue(section) !== shuntNodeId)
					return;
				if (asFlag) {
					if (String(value) === '1')
						uci.set('passwall', shuntNodeId, uciName, '1');
					else
						uci.unset('passwall', shuntNodeId, uciName);
					return;
				}
				if (value == null || value === '')
					uci.unset('passwall', shuntNodeId, uciName);
				else
					uci.set('passwall', shuntNodeId, uciName, value);
			};
			option.remove = function(section) {
				uci.unset('passwall', section, option.option);
				if (nodeOpt.formvalue(section) !== shuntNodeId)
					return;
				uci.unset('passwall', shuntNodeId, uciName);
			};
			option.depends('node', shuntNodeId);
		}

		if (showShunt) {
			if (loadedObj.type === 'Xray') {
				o = s.taboption('Shunt', form.ListValue, 'domainStrategy', _('Domain Strategy'));
				o.value('AsIs');
				o.value('IPIfNonMatch');
				o.value('IPOnDemand');
				o.default = 'IPOnDemand';
				o.description = E('div', {}, [
					E('br'),
					ul([
						_("'AsIs': Only use domain for routing. Default value."),
						_("'IPIfNonMatch': When no rule matches current domain, resolves it into IP addresses (A or AAAA records) and try all rules again."),
						_("'IPOnDemand': As long as there is a IP-based rule, resolves the domain into IP immediately.")
					])
				]);
				mirror(o, 'domainStrategy', false);
				o = s.taboption('Shunt', form.ListValue, 'domainMatcher', _('Domain matcher'));
				o.value('hybrid');
				o.value('linear');
				mirror(o, 'domainMatcher', false);
			}
			var fakeTitle = _('Use FakeDNS work in the domain that proxy.') + '\n' +
				_('Suitable scenarios for let the node servers get the target domain names.') + '\n' +
				_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
			o = s.taboption('Shunt', form.Flag, 'fakedns', E('span', {}, [
				E('a', { 'style': 'color:#FF8C00' }, 'FakeDNS'),
				' ' + _('Main switch')
			]), E('div', {}, [
				_('Use FakeDNS work in the domain that proxy.'),
				E('br'),
				_('Suitable scenarios for let the node servers get the target domain names.'),
				E('br'),
				_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.')
			]));
			mirror(o, 'fakedns', true);

			var shuntGroup = s.taboption('Shunt', form.ListValue, 'shunt_group', _('Shunt Rule Group'));
			shuntGroup.value('', _('default'));
			var seenGroups = {};
			(uci.sections('passwall', 'shunt_rules') || []).forEach(function(rule) {
				if (rule.group && !seenGroups[rule.group]) {
					seenGroups[rule.group] = true;
					shuntGroup.value(rule.group, rule.group);
				}
			});
			mirror(shuntGroup, 'shunt_group', false);
			shuntGroup.onchange = function(ev, section_id, value) {
				if (!value)
					uci.unset('passwall', shuntNodeId, 'shunt_group');
				else
					uci.set('passwall', shuntNodeId, 'shunt_group', value);
				uci.unset('passwall', section_id, 'shunt_group');
				uci.save().then(function() {
					window.location.reload();
				});
			};
		}

		function appendNodeLists(items) {
			var order = ['socks_list', 'normal_list', 'balancing_list', 'urltest_list', 'iface_list'];
			var seen = { 'shunt_list': true };
			order.forEach(function(key) { seen[key] = true; });
			function pushList(list) {
				(list || []).forEach(function(v) {
					items.push({
						value: v.id,
						label: v.remark,
						group: (v.group && v.group !== '') ? v.group : _('default')
					});
				});
			}
			order.forEach(function(key) { pushList(nodeList[key]); });
			Object.keys(nodeList).forEach(function(key) {
				if (seen[key])
					return;
				pushList(nodeList[key]);
			});
		}

		var shuntTable = null;
		if (showShunt) {
			var groupVal = String(uci.get('passwall', shuntNodeId, 'shunt_group') || '').toLowerCase();
			var rules = [];
			(uci.sections('passwall', 'shunt_rules') || []).forEach(function(e) {
				if (String(e.group || '').toLowerCase() === groupVal) {
					rules.push({
						id: e['.name'],
						remarks: e.remarks || e['.name'],
						nodeOption: e['.name'],
						nodeDefault: '',
						fakeOption: e['.name'] + '_fakedns',
						proxyOption: e['.name'] + '_proxy_tag',
						isDefault: false
					});
				}
			});
			rules.push({
				id: '.default',
				remarks: _('Default'),
				nodeOption: 'default_node',
				nodeDefault: '_direct',
				fakeOption: 'default_fakedns',
				proxyOption: 'default_proxy_tag',
				isDefault: true
			});
			var normalIds = {};
			(nodeList.normal_list || []).forEach(function(n) { normalIds[n.id] = true; });
			var preTitle = _('Set the node to be used as a pre-proxy.') + '\n' +
				_('Each rule has a separate switch that controls whether this rule uses the pre-proxy or not.');
			var fakeHead = _('Use FakeDNS work in the domain that proxy.') + '\n' +
				_('Suitable scenarios for let the node servers get the target domain names.') + '\n' +
				_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
			var body = [ E('tr', { 'class': 'cbi-section-table-titles' }, [
				E('th', { 'class': 'cbi-section-table-cell' }, _('Rule')),
				E('th', { 'class': 'cbi-section-table-cell' }, _('Node')),
				E('th', { 'class': 'cbi-section-table-cell' }, E('a', { 'style': 'color:#FF8C00', 'title': fakeHead }, 'FakeDNS')),
				E('th', { 'class': 'cbi-section-table-cell' }, E('a', { 'style': 'color:red', 'title': preTitle }, _('Preproxy')))
			])];
			rules.forEach(function(rule) {
				var curNode = uci.get('passwall', shuntNodeId, rule.nodeOption);
				if (curNode == null || curNode === '')
					curNode = rule.nodeDefault;
				var curProxy = uci.get('passwall', shuntNodeId, rule.proxyOption) || '';
				var curFake = uci.get('passwall', shuntNodeId, rule.fakeOption) === '1';
				var nodeItems = [
					{ value: '', label: _('Close (Not use)'), group: '' }
				];
				if (!rule.isDefault)
					nodeItems.push({ value: '_default', label: _('Use default node'), group: '' });
				nodeItems.push({ value: '_direct', label: _('Direct Connection'), group: '' });
				nodeItems.push({ value: '_blackhole', label: _('Blackhole (Block)'), group: '' });
				appendNodeLists(nodeItems);
				var proxyItems = [ { value: '', label: _('Close (Not use)'), group: '' } ];
				appendNodeLists(proxyItems);
				var nodeSel = buildSelect('pw-shunt-node-' + rule.id, nodeItems, curNode);
				var proxySel = buildSelect('pw-shunt-proxy-' + rule.id, proxyItems, curProxy);
				var fake = E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox' });
				if (curFake)
					fake.checked = true;
				nodeSel.setAttribute('data-shunt-option', rule.nodeOption);
				proxySel.setAttribute('data-shunt-option', rule.proxyOption);
				fake.setAttribute('data-shunt-option', rule.fakeOption);
				fake.setAttribute('data-shunt-flag', '1');
				function applyVisibility(persist) {
					var val = nodeSel.value;
					var showFake = !(val === '' || val === '_direct');
					fake.style.display = showFake ? '' : 'none';
					if (!showFake)
						fake.checked = false;
					var showProxy = !(!val || val.charAt(0) === '_' || val.indexOf('socks_') === 0 || !normalIds[val]);
					proxySel.style.display = showProxy ? '' : 'none';
					if (!showProxy)
						proxySel.value = '';
					if (persist && !showFake)
						uci.unset('passwall', shuntNodeId, rule.fakeOption);
					if (persist && !showProxy)
						uci.unset('passwall', shuntNodeId, rule.proxyOption);
				}
				nodeSel.addEventListener('change', function() {
					if (nodeSel.value === '')
						uci.unset('passwall', shuntNodeId, rule.nodeOption);
					else
						uci.set('passwall', shuntNodeId, rule.nodeOption, nodeSel.value);
					applyVisibility(true);
				});
				proxySel.addEventListener('change', function() {
					if (!proxySel.value)
						uci.unset('passwall', shuntNodeId, rule.proxyOption);
					else
						uci.set('passwall', shuntNodeId, rule.proxyOption, proxySel.value);
				});
				fake.addEventListener('change', function() {
					if (fake.checked)
						uci.set('passwall', shuntNodeId, rule.fakeOption, '1');
					else
						uci.unset('passwall', shuntNodeId, rule.fakeOption);
				});
				applyVisibility(false);
				var ruleCell = rule.isDefault
					? E('font', { 'style': 'color: red' }, rule.remarks)
					: E('a', { 'href': pw.pageUrl('shunt_rules', rule.id), 'target': '_blank' }, rule.remarks);
				var edit = E('a', {
					'href': '#',
					'click': function(ev) {
						ev.preventDefault();
						var val = nodeSel.value;
						if (!val || val.indexOf('tcp') === 0 || val.indexOf('_default') === 0 || val.indexOf('_direct') === 0 || val.indexOf('_blackhole') === 0)
							return;
						window.location.href = (val.indexOf('socks_') === 0)
							? pw.pageUrl('socks_config', val)
							: pw.pageUrl('node_config', val);
					}
				}, _('Edit'));
				body.push(E('tr', { 'class': 'cbi-section-table-row' }, [
					E('td', { 'class': 'cbi-section-table-cell' }, ruleCell),
					E('td', { 'class': 'cbi-section-table-cell' }, [ nodeSel, ' ', edit ]),
					E('td', { 'class': 'cbi-section-table-cell' }, fake),
					E('td', { 'class': 'cbi-section-table-cell' }, proxySel)
				]));
			});
			shuntTable = E('div', { 'id': 'cbi-passwall-shunt_option_list', 'data-node-id': shuntNodeId, 'class': 'cbi-section' }, [
				E('table', { 'class': 'table cbi-section-table' }, body)
			]);
		}

		var s2 = m.section(form.GridSection, 'socks', _('Socks Config'));
		s2.anonymous = true;
		s2.addremove = true;
		s2.sortable = true;
		s2.nodescriptions = true;
		s2.extedit = pw.pageUrl('socks_config') + '/%s';
		s2.handleAdd = function() {
			var uid = 'socks_' + pw.rand(5);
			var n = 1;
			(uci.sections('passwall', 'socks') || []).forEach(function() { n++; });
			var configName = this.uciconfig || this.map.config;
			this.uci.add(configName, 'socks', uid);
			this.uci.set(configName, uid, 'port', String(1080 + n));
			this.uci.set(configName, uid, 'http_port', '0');
			return this.map.save().then(function() {
				window.location.href = pw.pageUrl('socks_config', uid);
			});
		};
		s2.handleRemove = function(section_id, ev) {
			var nodeSecs = uci.sections('passwall', 'nodes') || [];
			var newNode = nodeSecs.length ? nodeSecs[0]['.name'] : '';
			if ((uci.get('passwall', sid, 'node') || '') === section_id)
				uci.set('passwall', sid, 'node', newNode);
			(uci.sections('passwall', 'acl_rule') || []).forEach(function(rule) {
				if (rule.node === section_id)
					uci.set('passwall', rule['.name'], 'node', 'default');
			});
			nodeSecs.forEach(function(node) {
				var listName = null;
				if (node.urltest_node != null && node.urltest_node !== '')
					listName = 'urltest_node';
				else if (node.balancing_node != null && node.balancing_node !== '')
					listName = 'balancing_node';
				if (listName) {
					var list = uci.get('passwall', node['.name'], listName) || [];
					if (!Array.isArray(list))
						list = [list];
					var kept = [];
					var changed = false;
					list.forEach(function(item) {
						if (item === section_id)
							changed = true;
						else
							kept.push(item);
					});
					if (changed)
						uci.set('passwall', node['.name'], listName, kept);
				}
				if (node.fallback_node === section_id)
					uci.unset('passwall', node['.name'], 'fallback_node');
			});
			return form.GridSection.prototype.handleRemove.call(this, section_id, ev);
		};

		o = s2.option(form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;
		o.modalonly = false;

		var socksNode = s2.option(form.ListValue, 'node', _('Socks Node'));
		socksNode.modalonly = false;

		o = s2.option(form.DummyValue, 'now_node', _('Current Node'));
		o.modalonly = false;
		o.renderWidget = function(section_id) {
			var holder = E('div', { 'id': 'pw-now-' + section_id, 'data-socks-id': section_id });
			var cache = pw.parseRuntime(cacheText);
			var nid = cache[section_id];
			remarkNode(holder, nid ? (remarks[nid] || nid) : '');
			return holder;
		};

		o = s2.option(form.DummyValue, 'port_status', _('Port Status'));
		o.modalonly = false;
		o.renderWidget = function(section_id) {
			var socks = uci.get('passwall', section_id, 'port') || '0';
			var http = uci.get('passwall', section_id, 'http_port') || '0';
			return E('div', { 'class': '_socks_status', 'socks_id': section_id }, [
				E('span', { 'class': '_socks' }),
				' SOCKS: ' + socks,
				E('br'),
				E('span', { 'class': '_http' }),
				' HTTP: ' + http
			]);
		};

		var mainItems = [ { value: '', label: _('Close'), group: '' } ];
		if (hasCore) {
			(nodeList.socks_list || []).forEach(function(v) {
				mainItems.push({ value: v.id, label: v.remark, group: groupName(v) });
			});
		}
		if (hasNormal) {
			nodes.forEach(function(v) {
				var id = nodeIdOf(v);
				if (v.protocol === '_shunt') {
					if (!hasCore)
						return;
					shuntIds[id] = true;
					shuntSel.depends({ node: id });
					if (v.type === 'Xray')
						xrayDns.depends({ node: id });
					else {
						singDns.depends({ node: id });
						rewriteTtl.depends({ node: id });
					}
				}
				mainItems.push({ value: id, label: v.remark, group: groupName(v) });
			});
		}
		groupedNode(nodeOpt, mainItems, { flag: setShuntFlag });
		nodeOpt.onchange = function(ev, section_id, value) {
			if (shuntIds[value] && value !== loadedNode) {
				uci.set('passwall', section_id, 'node', value);
				uci.save().then(function() {
					window.location.reload();
				});
			}
		};

		var socksItems = [];
		if (hasNormal) {
			nodes.forEach(function(v) {
				if (v.type === 'Socks' && !hasCore)
					return;
				socksItems.push({ value: nodeIdOf(v), label: v.remark, group: groupName(v) });
			});
		}
		groupedNode(socksNode, socksItems, null);

		this._flushShunt = function() {
			if (!shuntTable)
				return;
			var nodeId = shuntTable.getAttribute('data-node-id');
			if (nodeOpt.formvalue(sid) !== nodeId)
				return;
			shuntTable.querySelectorAll('[data-shunt-option]').forEach(function(el) {
				var key = el.getAttribute('data-shunt-option');
				if (el.getAttribute('data-shunt-flag')) {
					if (el.checked)
						uci.set('passwall', nodeId, key, '1');
					else
						uci.unset('passwall', nodeId, key);
				}
				else if (!el.value) {
					uci.unset('passwall', nodeId, key);
				}
				else {
					uci.set('passwall', nodeId, key, el.value);
				}
			});
		};

		var refreshDnsLog = function() {};
		dnsShunt.onchange = function() { refreshDnsLog(); };

		function qid(scope, id) {
			if (!scope)
				return null;
			if (scope.id === id)
				return scope;
			return scope.querySelector('[id="' + String(id).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"]');
		}

		var self = this;
		return m.render().then(function(formNode) {
			rootKids.push(formNode);
			var root = E('div', {}, rootKids);
			var tab = qid(root, 'container.passwall.' + sid + '.socks');
			var grid = qid(root, 'cbi-passwall-socks');
			var socksEnabled = qid(root, 'cbi-passwall-' + sid + '-socks_enabled');
			if (tab && socksEnabled)
				tab.appendChild(socksEnabled);
			if (tab && grid)
				tab.appendChild(grid);
			if (shuntTable) {
				var shuntBox = qid(root, 'container.passwall.' + sid + '.Shunt');
				if (shuntBox)
					shuntBox.appendChild(shuntTable);
			}
			var dnsEl = qid(root, dnsShunt.cbid(sid));
			refreshDnsLog = function() {
				if (!dnsEl || !dnsEl.parentNode)
					return;
				var old = dnsEl.parentNode.querySelector('a.dns-log-link');
				if (old)
					old.parentNode.removeChild(old);
				var val = dnsShunt.formvalue(sid);
				if (val !== 'chinadns-ng' && val !== 'smartdns')
					return;
				dnsEl.parentNode.appendChild(E('a', {
					'href': '#',
					'class': 'dns-log-link',
					'style': 'margin-left:10px',
					'click': function(ev) {
						ev.preventDefault();
						var cur = dnsShunt.formvalue(sid);
						if (cur === 'smartdns')
							openLog(pw.get('get_smartdns_log'));
						else
							openLog(pw.get('get_chinadns_log', { flag: 'default' }));
					}
				}, _('Log')));
			};
			refreshDnsLog();
			if (dnsEl)
				dnsEl.addEventListener('change', refreshDnsLog);

			function attachNodeLinks(select, mode, socksId) {
				if (!select || !select.parentNode || select.parentNode.querySelector('.node-actions'))
					return;
				var box = E('div', {
					'class': 'node-actions',
					'style': 'display:inline-flex;align-items:center;gap:4px;flex-wrap:wrap;margin-left:4px;'
				}, [
					E('a', {
						'href': '#',
						'click': function(ev) {
							ev.preventDefault();
							var val = select.value;
							if (!val || val.indexOf('tcp') === 0 || val.indexOf('_default') === 0 || val.indexOf('_direct') === 0 || val.indexOf('_blackhole') === 0)
								return;
							window.location.href = (val.indexOf('socks_') === 0)
								? pw.pageUrl('socks_config', val)
								: pw.pageUrl('node_config', val);
						}
					}, _('Edit')),
					E('a', {
						'href': '#',
						'click': function(ev) {
							ev.preventDefault();
							if (mode === 'socks')
								openLog(pw.get('get_socks_log', { name: socksId }));
							else
								openLog(pw.get('get_redir_log', { id: 'default' }));
						}
					}, _('Log'))
				]);
				select.parentNode.appendChild(box);
			}
			attachNodeLinks(qid(root, nodeOpt.cbid(sid)), 'global');
			(uci.sections('passwall', 'socks') || []).forEach(function(sec) {
				attachNodeLinks(qid(root, 'cbid.passwall.' + sec['.name'] + '.node'), 'socks', sec['.name']);
			});

			var directField = qid(root, 'cbi-passwall-' + sid + '-smartdns_direct_dns');
			if (directField) {
				var updateDirect = function() {
					var list = directField.querySelector('.cbi-dynlist');
					if (!list)
						return;
					var inputs = list.querySelectorAll('.item > input[type="hidden"]');
					var hasDns = false;
					for (var i = 0; i < inputs.length; i++) {
						if (String(inputs[i].value || '').trim() !== '')
							hasDns = true;
					}
					var text = hasDns ? _('-- Please choose --') : _('Auto');
					var placeholder = list.querySelector('.add-item .cbi-dropdown > ul > li[placeholder]');
					if (placeholder && placeholder.textContent !== text)
						placeholder.textContent = text;
					var input = list.querySelector('.add-item > input[type="text"]');
					if (input)
						input.placeholder = hasDns ? '' : _('Auto');
				};
				new MutationObserver(updateDirect).observe(directField, { childList: true, subtree: true });
				updateDirect();
			}

			poll.add(function() {
				return Promise.all([
					pw.get('index_status'),
					pw.get('get_now_use_node'),
					fs.read(CACHE_VAR).catch(function() { return ''; })
				]).then(function(res) {
					paintIndex(res[0]);
					paintNowNode(res[1], remarks);
					paintSocksRuntime(pw.parseRuntime(res[2]), remarks);
					return paintSocksPorts();
				});
			}, 5);

			self.map = m;
			return root;
		});
	},

	handleSave: function(ev) {
		if (typeof this._flushShunt === 'function')
			this._flushShunt();
		return this.super('handleSave', [ev]);
	}
});
