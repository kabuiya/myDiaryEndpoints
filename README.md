    My diary project (API ENDPOINTS)
[![CircleCI](https://dl.circleci.com/status-badge/img/circleci/3WDH8NqBWqqcfhediMABwD/7604d3a9-e056-4aba-b688-41eadd483819/tree/main.svg?style=svg&circle-token=CCIPRJ_KcSEMznZ38G7aY3HN41vT_5390d1e96a0b759451f6a408c6b7bd9e14f43f40)](https://dl.circleci.com/status-badge/redirect/circleci/3WDH8NqBWqqcfhediMABwD/7604d3a9-e056-4aba-b688-41eadd483819/tree/main)
[![Coverage Status](https://coveralls.io/repos/github/kabuiya/myDiaryEndpoints/badge.svg)](https://coveralls.io/github/kabuiya/myDiaryEndpoints)

# My Diary Project, API endpoints
Welcome to My Diary Project! This project aims to provide a simple and intuitive diary application where users can record their thoughts, feelings, and experiences.


# API endpoints
    
    | Method | Endpoint                 | Description                           |
    |--------|--------------------------|-------------------------------------- |
    | POST   | /api/v1/register         | register new user                     |
    | POST   | /api/v1/login            | login  user                           |
    | POST   | /api/v1/logout           | logout  user                          |
    | GET    | /api/v1/profile          | Get user (profile)                    |
    | PUT    | /api/v1/profile/update   | update user profile                   |
    | DELETE | /api/v1/del_account      | delete user acc.                      |
    | POST   | /api/v1/add_entries      | Add diary content                     |
    | GET    | /api/v1/get_entries      | get users diary items                 |
    | GET    | /api/v1/get_entry/:id    | get a diary content with id           |
    | PUT    | /api/v1/update_entry/:id | update a diary content with entry id  |
    | DELETE | /api/v1/delete_entry/:id | get a diary content with entry id     |
    

## Features

    - **User Authentication:** Users can sign up for an account and log in securely.
    - **Create Entries:** Users can create new diary entries, each with a title, date, and content.
    - **View Entries:** Users can view their previously created diary entries.
    - **Edit Entries:** Users can edit the content of existing diary entries.
    - **Delete Entries:** Users can delete diary entries they no longer wish to keep.

## Technologies Used

 - **Frontend:** HTML, CSS, JavaScript, React
  - [Frontend with JS](https://github.com/kabuiya/myjournal)
  - [Frontend with React](https://github.com/kabuiya/my-Journal)
- **Backend:** Python, Flask RESTful
- **Database:** PostgreSQL (chosen based on project requirements)
- **Authentication:** JSON Web Tokens (JWT) for authentication and authorization
- **Testing:** Unit tests written with unittest
- **Continuous Integration:** Integrated with CircleCI
- **Continuous Coverage:** Utilizes coverage tools to measure test coverage (coveralls), it's not working

## Getting Started:
**To run this application locally, follow these steps:**

    1. Clone this repository to your local machine.
    2. Navigate to the project directory in your terminal.
    3. Install dependencies by running `pip install`.
    4. Start the server.
    5. Access the application in your web browser at `http://localhost:5000`.

## Running Tests
**To run the unit tests, execute the following command:**
    `python -m unittest discover tests`

# License
    This project is licensed under the MIT License 

# Acknowledgments
    This project was inspired by similar diary applications.


