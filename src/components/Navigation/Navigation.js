import React from 'react';
import {Alignment, Navbar, NavbarDivider, NavbarGroup, NavbarHeading} from '@blueprintjs/core';
import NavLink from "./NavLink/NavLink";

class Navigation extends React.Component {
    render() {
        return (
            <nav>
                <Navbar>
                    <NavbarGroup align={Alignment.LEFT}>
                        <NavbarHeading>
                            Blog
                        </NavbarHeading>
                        <NavbarDivider/>
                        <NavLink to="/" icon="home" label="Home"/>
                        <NavLink to="/login" icon="user" label="Login"/>
                    </NavbarGroup>
                    <NavbarGroup align={Alignment.RIGHT}>
                        <NavLink to="/login" icon="user" label="Login"/>
                    </NavbarGroup>
                </Navbar>
            </nav>
        )
    }
}

export default Navigation;